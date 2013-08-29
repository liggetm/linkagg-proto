/*
 *
 * (C) 2005-12 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pthread.h>

#include "pfring.h"
#include "pfutils.c"

static const int MAX_DEVICES_SUPPORTED = 4;
struct packet {
  u_int16_t len;
  u_int64_t ticks_from_beginning;
  char *pkt;
  struct packet *next;
};

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int32_t	ihl:4,		/* header length */
    version:4;			/* version */
#else
  u_int32_t	version:4,			/* version */
    ihl:4;		/* header length */
#endif
  u_int8_t	tos;			/* type of service */
  u_int16_t	tot_len;			/* total length */
  u_int16_t	id;			/* identification */
  u_int16_t	frag_off;			/* fragment offset field */
  u_int8_t	ttl;			/* time to live */
  u_int8_t	protocol;			/* protocol */
  u_int16_t	check;			/* checksum */
  u_int32_t saddr, daddr;	/* source and dest address */
};

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
};

struct packet *pkt_head = NULL;
pfring_stat pfringStats;
char *in_dev = NULL;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
u_int64_t num_pkt_good_sent = 0, last_num_pkt_good_sent = 0;
u_int64_t num_bytes_good_sent = 0, last_num_bytes_good_sent = 0;
struct timeval lastTime, startTime;
int reforge_mac = 0;
char mac_address[6];
int send_len = 60;
u_char buffer[9000];
u_int32_t num_to_send = 0;
struct packet *tosend;
int num_of_devices;

/* *************************************** */

void print_stats(pfring* pd, char* dev) {
  double deltaMillisec, avgThpt, avgThptBits, avgThptBytes;
  struct timeval now;
  char buf3[64], buf4[64], buf5[64], statsBuf[512], timebuf[128];
  u_int64_t deltaMillisecStart;

  gettimeofday(&now, NULL);
  deltaMillisec = delta_time(&now, &lastTime);

  deltaMillisec = delta_time(&now, &startTime);
  avgThpt = (double)(num_pkt_good_sent * 1000)/deltaMillisec;
  avgThptBytes = (double)(num_bytes_good_sent * 1000)/deltaMillisec;
  avgThptBits = avgThptBytes * 8;

  snprintf(statsBuf, sizeof(statsBuf),
	   "%s TX rate: [average %s pps/%s Gbps][total %s pkts]",
	   dev,
	   pfring_format_numbers(avgThpt, buf3, sizeof(buf3), 1),
	   pfring_format_numbers(avgThptBits/(1000*1000*1000),  buf4, sizeof(buf4), 1),
	   pfring_format_numbers(num_pkt_good_sent, buf5, sizeof(buf5), 1));
  
  fprintf(stdout, "%s\n", statsBuf);

  deltaMillisecStart = delta_time(&now, &startTime);
  snprintf(statsBuf, sizeof(statsBuf),
           "Duration:          %s\n"
           "SentPackets:       %lu\n"
           "SentBytes:         %lu\n",
           sec2dhms((deltaMillisecStart/1000), timebuf, sizeof(timebuf)),
           (long unsigned int) num_pkt_good_sent,
           (long unsigned int) num_bytes_good_sent);
  pfring_set_application_stats(pd, statsBuf);

  memcpy(&lastTime, &now, sizeof(now));
  last_num_pkt_good_sent = num_pkt_good_sent, last_num_bytes_good_sent = num_bytes_good_sent;
}

/* ******************************** */

void my_sigalarm(int sig) {
  //print_stats();
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  //print_stats();
  printf("Sent %llu packets\n", (long long unsigned int)num_pkt_good_sent);
  //pfring_close(pd);

  /* TODO: need to close rings here, in case app doesn't run to completion */

  exit(0);
}

/* *************************************** */

void printHelp(void) {
  printf("linkaggtx\n");
  printf("Hacked version of pfsend - allows a list of interfaces.\n\n");
  printf("linkaggtx -i out_dev [-h]\n"
         "       [-l <length>] [-n <num>]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-n <num>        Num pkts to send (use 0 for infinite)\n");
  exit(0);
}

/* ******************************************* */

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf,
			  unsigned nbytes, u_int32_t sum) {
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

/* ******************************************* */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

static void forge_udp_packet(u_char *buffer, u_int buffer_len, u_int idx) {
  int i;
  struct ip_header *ip_header;
  struct udp_header *udp_header;
  u_int32_t src_ip = (0x0A000000 + idx) % 0xFFFFFFFF /* from 10.0.0.0 */;
  u_int32_t dst_ip =  0xC0A80001 /* 192.168.0.1 */;
  u_int16_t src_port = 2012, dst_port = 3000;

  /* Reset packet */
  memset(buffer, 0, buffer_len);

  for(i=0; i<12; i++) buffer[i] = i;
  buffer[12] = 0x08, buffer[13] = 0x00; /* IP */
  if(reforge_mac) memcpy(buffer, mac_address, 6);

  ip_header = (struct ip_header*) &buffer[sizeof(struct ether_header)];
  ip_header->ihl = 5;
	ip_header->version = MAX_DEVICES_SUPPORTED;
  ip_header->tos = 0;
  ip_header->tot_len = htons(send_len-sizeof(struct ether_header));
  ip_header->id = htons(2012);
  ip_header->ttl = 64;
  ip_header->frag_off = htons(0);
  ip_header->protocol = IPPROTO_UDP;
  ip_header->daddr = htonl(dst_ip);
  ip_header->saddr = htonl(src_ip);
  ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header,
				      sizeof(struct ip_header), 0));

  udp_header = (struct udp_header*)(buffer + sizeof(struct ether_header) + sizeof(struct ip_header));
  udp_header->source = htons(src_port);
  udp_header->dest = htons(dst_port);
  udp_header->len = htons(send_len-sizeof(struct ether_header)-sizeof(struct ip_header));
  udp_header->check = 0; /* It must be 0 to compute the checksum */

  /*
    http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
    http://www.ietf.org/rfc/rfc0761.txt
    http://www.ietf.org/rfc/rfc0768.txt
  */

  i = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
  udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udp_header),
                                       in_cksum((unsigned char *)&buffer[i], send_len-i,
						in_cksum((unsigned char *)&ip_header->saddr,
							 2*sizeof(ip_header->saddr),
							 IPPROTO_UDP + ntohs(udp_header->len)))));
}

static void setup_packets() {
	forge_udp_packet(buffer, sizeof(buffer), 0);
	struct packet *p = (struct packet *) malloc(sizeof(struct packet));
	struct packet *last = NULL;
	  if(p) {
		  pkt_head = p;

		  p->len = send_len;
		  p->ticks_from_beginning = 0;
		  p->next = pkt_head;
		  p->pkt = (char*)malloc(p->len);

		  if (p->pkt == NULL) {
			  printf("Not enough memory\n");
		  }

		  memcpy(p->pkt, buffer, send_len);

		  if (last != NULL) last->next = p;
		  last = p;
	  } else {
		  /* oops, couldn't allocate memory */
		  fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
	  }
}

/* *************************************** */

/*
 * Open and enable the list of devices
 */
static void enable_rings(char* devices[], pfring* rings[]) {

	int i = 0;
	for(i=0; i < num_of_devices; i++) {

		pfring *ring = pfring_open(devices[i], 1500, 0);

		if(ring == NULL) {
			printf("pfring_open %s error [%s]\n", (char *) devices[i], strerror(errno));
		} else {
			printf("Sending packets on %s\n", (char *)devices[i]);
			pfring_set_socket_mode(ring, send_only_mode);

			if(pfring_enable_ring(ring) != 0) {
				printf("Unable to enable ring :-(\n");
				pfring_close(ring);
			} else {
				rings[i] = ring;
			}
		}
	}
}

static void disable_rings(pfring* rings[]) {
	  int k = 0;
	  for(k=0; k < num_of_devices; k++) {
		  pfring_close(rings[k]);
		  //print_stats(rings[k], device_names[k]);
	  }
}

static void transmit_packets(pfring* rings[]) {

	int device_idx = 0, i = 0;
	printf ("\nStarting transmission...\n");

	  while((num_to_send == 0) || (i < num_to_send)) {
	    int rc;

	  redo:

	  //printf("num_to_send = %u\n", num_to_send);
	  rc = pfring_send(rings[device_idx], tosend->pkt, tosend->len, 0);

	    if(rc == PF_RING_ERROR_INVALID_ARGUMENT){
	      printf("Attempting to send invalid packet");
	    } else if(rc < 0) {
	    	/* Not enough space in buffer */
	    	usleep(1);
	    	goto redo;
	    }

	    num_pkt_good_sent++;
	    num_bytes_good_sent += tosend->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

	    tosend = tosend->next;

	    if(num_to_send > 0)
	    	i++;
	    device_idx++;
	    if(device_idx == num_of_devices)
	    	device_idx = 0;

	  }

	  printf ("\n...ended transmission of %u packets.\n", num_to_send);

}

void *transmit_thread(void *arg) {
	transmit_packets((pfring**) arg);
	return(0);
}

int main(int argc, char* argv[]) {
  int c;

  while((c = getopt(argc, argv, "hi:n:l:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'n':
      num_to_send = atoi(optarg);
      break;
    case 'l':
      send_len = atoi(optarg);
      break;

    default:
      printHelp();
    }
  }

  if(optind < argc) /* Extra argument */
    printHelp();

  const char separator[2] = ",";
  char *token = strtok(in_dev, separator);	/* Get first device */
  char* devices[MAX_DEVICES_SUPPORTED];
  devices[0] = token;
  int i=1;

  while( token != NULL )
  {
	  if(i <= MAX_DEVICES_SUPPORTED) {
		  token = strtok(NULL, separator);
		  devices[i] = token;
		  i++;
	  } else {
		  printf("Maximum 4 comma separated device names. eg; eth1,eth2,eth3,eth4\n");
		  return(1);
	  }
  }

  num_of_devices = i - 1;
  char* device_names[num_of_devices];

  i = 0;
  for(i = 0; i < num_of_devices; i++) {
	  device_names[i] = devices[i];
  }

  pfring* rings[num_of_devices];
  enable_rings(device_names, rings);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  setup_packets();
  tosend = pkt_head;
  printf("No. of active devices: %u\n", num_of_devices);

  gettimeofday(&startTime, NULL);
  memcpy(&lastTime, &startTime, sizeof(startTime));

  pthread_t pth;
  pthread_create(&pth, NULL, transmit_thread, &rings);

  //TODO: add functionality to dynamically change rings.

  pthread_join(pth, NULL);
  disable_rings(rings);

  return(0);
}
