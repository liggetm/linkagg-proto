/*
 *	The MIT License (MIT)
 *
 *	Copyright (c) 2013 Mark Liggett
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy of
 *	this software and associated documentation files (the "Software"), to deal in
 *	the Software without restriction, including without limitation the rights to
 *	use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 *	the Software, and to permit persons to whom the Software is furnished to do so,
 *	subject to the following conditions:
 *
 *	The above copyright notice and this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 *	FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 *	COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *	IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
*/


#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
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

static const char REMOVE_MEMBER_INPUT = '-';
static const char ADD_MEMBER_INPUT = '+';
static const int MAX_DEVICES_SUPPORTED = 4;
struct packet *pkt_head = NULL;
char *devices_arg = NULL;
u_int8_t do_shutdown = 0;
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
pthread_mutex_t device_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Circular packet linked-list
 */
struct packet {
  u_int16_t len;
  char *pkt;
  struct packet *next;
};

/**
 * IP Header definition
 */
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

/**
 * Udp protocol header. Per RFC 768, September, 1981.
 *
 */
struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
};

/**
 * Maps a physical device to a pf ring.  Has an enabled or disabled member field.
 */
struct tx_device {
	char* name;		/* standard device name eg; eth0 */
	bool enabled;	/* is device used for transmission */
	pfring* ring;
};

void my_sigalarm(int sig) {
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  printf("Sent %llu packets\n", (long long unsigned int)num_pkt_good_sent);

  /* TODO: need to close rings here, in case app doesn't run to completion */

  exit(0);
}

void printHelp(void) {
  printf("linkaggtx\n");
  printf("Aggregate link transmission prototype - allows the list of\ntransmission interfaces to be changed dynamically.\n");
  printf("linkaggtx -i out_dev [-h]\n"
         "       [-l <length>] [-n <num>]\n\n");
  printf("-h              Print this help\n");
  printf("-i <list_of_devices>     Comma separated list of devices.\n");
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

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

/**
 * Construct a valid IP header for the tx packets
 */
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

/**
 * Setup a tx packet with a circular reference to itself.
 */
static void setup_packets() {
	forge_udp_packet(buffer, sizeof(buffer), 0);
	struct packet *p = (struct packet *) malloc(sizeof(struct packet));
	struct packet *last = NULL;
	  if(p) {
		  pkt_head = p;

		  p->len = send_len;
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

/**
 * Indicate whether stdin is ready to be read. eg; Has pending character data.
 */
static int has_kb_input()
{
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

/*
 * Open ring for the given device.
 *
 * @param tx_device the device to open a ring for.
 */
static int enable_ring(struct tx_device *device_to_enable) {

	pfring *ring = pfring_open(device_to_enable->name, 1500, 0);

	if(ring == NULL) {
		printf("pfring_open %s error [%s]\n", device_to_enable->name, strerror(errno));
	} else {
		pfring_set_socket_mode(ring, send_only_mode);

		if(pfring_enable_ring(ring) != 0) {
			printf("Unable to enable ring :-(\n");
			pfring_close(ring);
		} else {
			device_to_enable->ring=ring;
			printf("Sending packets on %s\n", device_to_enable->name);
			return 1;
		}
	}
	return 0;
}

/**
 * Gracefully disable the tx_device if it is enabled.
 *
 * @param dev* the tx_device to be disabled.
 */
static void disable_ring(struct tx_device *dev) {
	pfring_close(dev->ring);
	dev->ring = NULL;
	//print_stats(rings[k], device_names[k]);
}

/**
 * Iterates across the tx_devices and if enabled tx a
 * packet, otherwise move to the next device.
 *
 * @param tx_device*[] a list of tx_devices*
 */
static void tx_packets(struct tx_device* enabled_devices[]) {

	int device_idx = 0, i = 0;
	bool tx_ready = false;

	for(i = 0; i < num_of_devices; i++) {
		if(!tx_ready && (enabled_devices[i]->enabled)) {
			tx_ready = true;
		}
	}

	if(!tx_ready) {
		printf("No available tx devices\n");
		exit(1);
	}

	printf ("\nStarting transmission...\n");
	fflush(stdout);

	  while((num_to_send == 0) || (i < num_to_send)) {
	    int rc;

	    while(!enabled_devices[device_idx]->enabled) {
	    	device_idx++;
	    	if(device_idx == num_of_devices)
	    		device_idx = 0;
	    }

	  redo:

		  rc = pfring_send(enabled_devices[device_idx]->ring, tosend->pkt, tosend->len, 0);


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
	  fflush(stdout);
}

/**
 * Spawn a transmission thread on the active devices
 *
 * @param void* the array of structs containing the tx_devices*
 */
void *tx_thread(void *arg) {
	tx_packets((struct tx_device**) arg);
	return(0);
}

/**
 * Disable transmissions on the given device.
 *
 * @param	tx_device* the device to be disabled.
 */
static void disable_device(struct tx_device* device) {
	if(device->enabled) {
		pthread_mutex_lock(&device_mutex);
		device->enabled = false;
		pthread_mutex_unlock(&device_mutex);
	}
}

/**
 * Enable transmissions on the given device.
 *
 * @param	tx_device* the device to be enabled.
 */
static void enable_device(struct tx_device* device) {
	if(!device->enabled) {
		pthread_mutex_lock(&device_mutex);
		device->enabled = true;
		pthread_mutex_unlock(&device_mutex);
	}
}

int main(int argc, char* argv[]) {
  int c;

  while((c = getopt(argc, argv, "hi:n:l:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      devices_arg = strdup(optarg);
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

  if(optind < argc)
	  printHelp();

  const char separator[2] = ",";
  char *token = strtok(devices_arg, separator);	/* Get first device */
  char* device_name_list[MAX_DEVICES_SUPPORTED];
  device_name_list[0] = token;
  int i=1;

  while( token != NULL )
  {
	  if(i <= MAX_DEVICES_SUPPORTED) {
		  token = strtok(NULL, separator);
		  device_name_list[i] = token;
		  i++;
	  } else {
		  printHelp();
	  }
  }

  num_of_devices = (i - 1);
  int active_devices = 0;
  struct tx_device *device_list[num_of_devices];

  for(i = 0; i < num_of_devices; i++) {
	  struct tx_device *dev = malloc(sizeof(struct tx_device));
	  dev->name = device_name_list[i];
	  dev->enabled = true;
	  active_devices += enable_ring(dev);
	  device_list[i] = dev;
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  setup_packets();
  tosend = pkt_head;
  printf("No. of active devices: %u\n", active_devices);

  gettimeofday(&startTime, NULL);
  memcpy(&lastTime, &startTime, sizeof(startTime));

  pthread_t tx_thread_id;
  pthread_create(&tx_thread_id, NULL, tx_thread, &device_list);

  int kb_struck = false;
  do {
	  char kb_input;
	  usleep(1);
	  kb_struck = has_kb_input();

	  if (kb_struck)
	  {
		  kb_input = fgetc(stdin);
		  if ((kb_input == ADD_MEMBER_INPUT) && (active_devices < num_of_devices)) {

			  enable_device(device_list[active_devices]);
			  printf("...member %s enabled\n", device_list[active_devices]->name);
			  active_devices++;

		  } else if ((kb_input == REMOVE_MEMBER_INPUT) && (active_devices > 1)) {

			  disable_device(device_list[active_devices - 1]);
			  printf("...member %s disabled\n", device_list[active_devices - 1]->name);
			  active_devices--;

		  }
	  }

	  kb_struck = false;

  } while ((pthread_kill(tx_thread_id, 0) != ESRCH) && !kb_struck);

  pthread_join(tx_thread_id, NULL);
  for(i = 0; i < num_of_devices; i++) {
	  disable_ring(device_list[i]);
  }

  return(0);
}
