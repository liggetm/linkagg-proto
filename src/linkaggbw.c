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
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define DEFAULT_DEVICE     "eth0"
#define MAX_NUM_DEVS           64

pfring  *pd[MAX_NUM_DEVS];
struct pollfd pfd[MAX_NUM_DEVS];
int num_devs = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 0, do_shutdown = 0;
int poll_duration = DEFAULT_POLL_DURATION;

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  u_int64_t diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  double thpt;
  int i = 0;
  unsigned long long absolute_recv = 0, absolute_drop = 0;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  for(i=0; i<num_devs; i++) {
    if(pfring_stats(pd[i], &pfringStat) >= 0) {
      absolute_recv = pfringStat.recv;
      absolute_drop = pfringStat.drop;
    }
  }

  nBytes = numBytes;
  nPkts  = numPkts;

  {
    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)absolute_recv, (unsigned int)absolute_drop,
	    (unsigned int)(absolute_recv+absolute_drop),
	    absolute_recv == 0 ? 0 :
	    (double)(absolute_drop*100)/(double)(absolute_recv+absolute_drop));
    fprintf(stderr, "%s pkts - %s bytes", 
	    pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	    pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if(print_all)
      fprintf(stderr, " [%s pkt/sec - %s Mbit/sec]\n",
	      pfring_format_numbers((double)(nPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(thpt, buf2, sizeof(buf2), 1));
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      bytesDiff = nBytes - lastBytes;
      bytesDiff /= (1000*1000*1000)/8;

      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%s ms][%s pps/%s Gbps]\n",
	      (long long unsigned int)diff,
	      pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	      pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1)
	      );
    }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  for(i=0; i<num_devs; i++)
    pfring_close(pd[i]);

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */


/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if(t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if(dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* *************************************** */

void printHelp(void) {
  printf("linkaggbw\n");
  printf("Aggregate link realtime bandwidth prototype - produces aggregate bandwidth statistics \n from a list of given interfaces.\n");
  printf("-h              Print this help\n");
  printf("-i <list_of_devices>     Comma separated list of devices.\n");
}

/* *************************************** */

inline int bundlePoll() {
  int i;

  for(i=0; i<num_devs; i++) {
    pfring_sync_indexes_with_kernel(pd[i]);
    pfd[i].events  = POLLIN;
    pfd[i].revents = 0;
  }
  errno = 0;

  return poll(pfd, num_devs, poll_duration);
}

/* *************************************** */

void packetConsumer() {
  u_char *buffer;
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  int next = 0, hunger = 0;

  while (!do_shutdown) {

    if (pfring_is_pkt_available(pd[next])) {
      if (pfring_recv(pd[next], &buffer, 0, &hdr, 0 /* wait_for_packet */) > 0) {
        numPkts++;
	numBytes += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
      }

      hunger = 0;
    } else hunger++;
    
    if (wait_for_packet && hunger >= num_devs) {
      bundlePoll();
      hunger = 0;
    }

    next = (next+1) % num_devs;
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *devices = NULL, *dev = NULL, *tmp = NULL;
  char c, buf[32];
  u_char mac_address[6] = { 0 };
  int snaplen = DEFAULT_SNAPLEN, rc;
  packet_direction direction = rx_only_direction;
  u_int16_t cpu_percentage = 0;
  u_int32_t flags = 0;
  int i = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc, argv, "hi:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      devices = strdup(optarg);
      break;

    default:
      printHelp();
    }
  }

  if(devices == NULL) {
	  printf("Must specify a list of devices to collect bandwidth readings from.");
	  return(1);
  }

  if(wait_for_packet && (cpu_percentage > 0)) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  dev = strtok_r(devices, ",", &tmp);
  while(i<MAX_NUM_DEVS && dev != NULL) {
    flags |= PF_RING_PROMISC;
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */
    pd[i] = pfring_open(dev, snaplen, flags);

    if(pd[i] == NULL) {
      fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n",
	      strerror(errno), dev);
      return(-1);
    } 

    printf("Capturing from %s", dev);
    if(pfring_get_bound_device_address(pd[i], mac_address) == 0)
      printf(" [%s]\n", etheraddr_string(mac_address, buf));
    else
      printf("\n");

    if((rc = pfring_set_direction(pd[i], direction)) != 0)
      ; //fprintf(stderr, "pfring_set_direction returned [rc=%d][direction=%d]\n", rc, direction);

    if((rc = pfring_set_socket_mode(pd[i], recv_only_mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);


    pfd[i].fd = pfring_get_selectable_fd(pd[i]);

    pfring_enable_ring(pd[i]);

    dev = strtok_r(NULL, ",", &tmp);
    i++;
  }
  num_devs = i;

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);

  packetConsumer();

  alarm(0);
  sleep(1);

  for (i=0; i < num_devs; i++)
    pfring_close(pd[i]);

  return(0);
}
