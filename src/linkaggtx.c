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

#include "pfring.h"
#include "pfutils.c"

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
pfring  *pd, *pdother;
pfring_stat pfringStats;
char *in_dev = NULL;
char *in_devother = NULL;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
u_int64_t num_pkt_good_sent = 0, last_num_pkt_good_sent = 0;
u_int64_t num_bytes_good_sent = 0, last_num_bytes_good_sent = 0;
struct timeval lastTime, startTime;
int reforge_mac = 0;
char mac_address[6];
int send_len = 60;
int if_index = -1;

/* *************************************** */

int is_fd_ready(int fd) {
  struct timeval timeout = {0};
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(fd, &fdset);
  return (select(fd+1, &fdset, NULL, NULL, &timeout) == 1);
}

int read_packet_hex(u_char *buf, int buf_len) {
  int i = 0, d, bytes = 0;
  char c;
  char s[3] = {0};

  if (!is_fd_ready(fileno(stdin)))
    return 0;

  while ((d = fgetc(stdin)) != EOF) {
    if (d < 0) break;
    c = (u_char) d;
    if ((c >= '0' && c <= '9') 
     || (c >= 'a' && c <= 'f')
     || (c >= 'A' && c <= 'F')) {
      s[i&0x1] = c;
      if (i&0x1) {
        bytes = (i+1)/2;
        sscanf(s, "%2hhx", &buf[bytes-1]);
	if (bytes == buf_len) break;
      }
      i++;
    }
  }

  return bytes;
}

/* *************************************** */

void print_stats() {
  double deltaMillisec, currentThpt, avgThpt, currentThptBits, currentThptBytes, avgThptBits, avgThptBytes;
  struct timeval now;
  char buf1[64], buf2[64], buf3[64], buf4[64], buf5[64], statsBuf[512], timebuf[128];
  u_int64_t deltaMillisecStart;

  gettimeofday(&now, NULL);
  deltaMillisec = delta_time(&now, &lastTime);
  currentThpt = (double)((num_pkt_good_sent-last_num_pkt_good_sent) * 1000)/deltaMillisec;
  currentThptBytes = (double)((num_bytes_good_sent-last_num_bytes_good_sent) * 1000)/deltaMillisec;
  currentThptBits = currentThptBytes * 8;

  deltaMillisec = delta_time(&now, &startTime);
  avgThpt = (double)(num_pkt_good_sent * 1000)/deltaMillisec;
  avgThptBytes = (double)(num_bytes_good_sent * 1000)/deltaMillisec;
  avgThptBits = avgThptBytes * 8;

  snprintf(statsBuf, sizeof(statsBuf),
	   "TX rate: [current %s pps/%s Gbps][average %s pps/%s Gbps][total %s pkts]",
	   pfring_format_numbers(currentThpt, buf1, sizeof(buf1), 1),
	   pfring_format_numbers(currentThptBits/(1000*1000*1000), buf2, sizeof(buf2), 1),
	   pfring_format_numbers(avgThpt, buf3, sizeof(buf3), 1),
	   pfring_format_numbers(avgThptBits/(1000*1000*1000),  buf4, sizeof(buf4), 1),
	   pfring_format_numbers(num_pkt_good_sent, buf5, sizeof(buf5), 1));
  
  fprintf(stdout, "%s\n", statsBuf);

  deltaMillisecStart = delta_time(&now, &startTime);
  snprintf(statsBuf, sizeof(statsBuf),
           "Duration:          %s\n"
           "SentPackets:       %lu\n"
           "SentBytes:         %lu\n"
           "CurrentSentPps:    %lu\n"
           "CurrentSentBitps:  %lu\n",
           sec2dhms((deltaMillisecStart/1000), timebuf, sizeof(timebuf)),
           (long unsigned int) num_pkt_good_sent,
           (long unsigned int) num_bytes_good_sent,
	   (long unsigned int) currentThpt,
	   (long unsigned int) currentThptBits);
  pfring_set_application_stats(pd, statsBuf);

  memcpy(&lastTime, &now, sizeof(now));
  last_num_pkt_good_sent = num_pkt_good_sent, last_num_bytes_good_sent = num_bytes_good_sent;
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();
  printf("Sent %llu packets\n", (long long unsigned int)num_pkt_good_sent);
  pfring_close(pd);

  exit(0);
}

/* *************************************** */

void printHelp(void) {
  printf("pfsend - (C) 2011-13 ntop.org\n");
  printf("Replay synthetic traffic, or a pcap, or a packet in hex format from standard input.\n\n"); 
  printf("pfsend -i out_dev [-a] [-f <.pcap file>] [-g <core_id>] [-h]\n"
         "       [-l <length>] [-n <num>][-r <rate>] [-m <dst MAC>]\n"
	 "       [-w <TX watermark>] [-v]\n\n");
  printf("-a              Active send retry\n");
#if 0
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
#endif
  printf("-f <.pcap file> Send packets as read from a pcap file\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-n <num>        Num pkts to send (use 0 for infinite)\n");
  printf("-r <rate>       Rate to send (example -r 2.5 sends 2.5 Gbit/sec, -r -1 pcap capture rate)\n");
  printf("-m <dst MAC>    Reforge destination MAC (format AA:BB:CC:DD:EE:FF)\n");
  printf("-b <num>        Number of different IPs (balanced traffic)\n");
  printf("-w <watermark>  TX watermark (low value=low latency) [not effective on DNA]\n");
  printf("-z              Disable zero-copy, if supported [DNA only]\n");
  printf("-x <if index>   Send to the selected interface, if supported\n");
  printf("-v              Verbose\n");
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
  ip_header->version = 4;
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

/* *************************************** */

int main(int argc, char* argv[]) {
  char path[255] = { 0 };
  int c, i, verbose = 0, active_poll = 0;
  u_char buffer[9000];
  u_int32_t num_to_send = 0;
  double gbit_s = 0;
  ticks tick_start = 0, tick_delta = 0;
  struct packet *tosend;
  u_int num_tx_slots = 0;

  while((c = getopt(argc, argv, "hi:j:n:l:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'j':
      in_devother = strdup(optarg);
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

  if((in_dev == NULL) || (optind < argc)) /* Extra argument */
    printHelp();

  printf("Sending packets on %s\n", in_dev);

  pd = pfring_open(in_dev, 1500, 0 /* PF_RING_PROMISC */);
  if(pd == NULL) {
    printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "linkaggtx");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  /*
   * Other j device if present
   */
  if(in_devother != NULL) {
	  pdother = pfring_open(in_devother, 1500, 0 /* PF_RING_PROMISC */);
	  if(pdother == NULL) {
	    printf("pfring_open %s error [%s]\n", in_devother, strerror(errno));
	    return(-1);
	  }
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(send_len < 60)
    send_len = 60;

  struct packet *p = NULL, *last = NULL;
  int stdin_packet_len;

  if ((stdin_packet_len = read_packet_hex(buffer, sizeof(buffer))) > 0) {
	  send_len = stdin_packet_len;
  }


  if (stdin_packet_len <= 0) {
	  printf("Reforging udp packet\n");
	  forge_udp_packet(buffer, sizeof(buffer), i);
  }

  /* TODO else: reforge IP only */

  p = (struct packet *) malloc(sizeof(struct packet));
  if(p) {
	  if (i == 0) pkt_head = p;

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
	  return (-1);
  }

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(1);
  }

  gettimeofday(&startTime, NULL);
  memcpy(&lastTime, &startTime, sizeof(startTime));

  pfring_set_socket_mode(pd, send_only_mode);
  if(pdother != NULL)
	  pfring_set_socket_mode(pdother, send_only_mode);

  if(pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return(-1);
  }

  if(pfring_enable_ring(pdother) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return(-1);
  }

  tosend = pkt_head;
  i = 0;

  pfring_set_application_stats(pd, "Statistics not yet computed: please try again...");
  if(pfring_get_appl_stats_file_name(pd, path, sizeof(path)) != NULL)
    fprintf(stderr, "Dumping statistics on %s\n", path);

  while((num_to_send == 0) || (i < num_to_send)) {
    int idev_rc, jdev_rc;

  redo:

  idev_rc = pfring_send(pd, tosend->pkt, tosend->len, gbit_s < 0 ? 1 : 0 /* Don't flush (it does PF_RING automatically) */);
  jdev_rc = pfring_send(pdother, tosend->pkt, tosend->len, gbit_s < 0 ? 1 : 0 /* Don't flush (it does PF_RING automatically) */);

    if((idev_rc == PF_RING_ERROR_INVALID_ARGUMENT) || (idev_rc == PF_RING_ERROR_INVALID_ARGUMENT)){
      printf("Attempting to send invalid packet [len: %u][MTU: %u]%s\n",
	     tosend->len, pd->mtu_len,
      	     if_index != -1 ? " or using a wrong interface id" : "");
    } else if((idev_rc < 0) || (jdev_rc < 0)){
      /* Not enough space in buffer */
    	if(!active_poll) {
    		usleep(1);
    	}
      goto redo;
    }

    num_pkt_good_sent++;
    num_bytes_good_sent += tosend->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

    tosend = tosend->next;

    if(num_pkt_good_sent == num_tx_slots)
      tosend = pkt_head;

    if(gbit_s > 0) {
      /* rate set */
      while((getticks() - tick_start) < (num_pkt_good_sent * tick_delta)) ;
    } else if (gbit_s < 0) {
      /* real pcap rate */
      if (tosend->ticks_from_beginning == 0)
        tick_start = getticks(); /* first packet, resetting time */
      while((getticks() - tick_start) < tosend->ticks_from_beginning) ;
    }

    if(num_to_send > 0) i++;
  } /* for */

  print_stats(0);
  pfring_close(pd);
  pfring_close(pdother);

  return(0);
}
