#include <errno.h>
#include <error.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <math.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/wireless.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <zlib.h>

#include "create-interface.h"
#include "pkts.h"
#include "address_table.h"

#ifndef  NON_PACKET_MMAP
static int create_ring(in_info *handle);
static void destroy_ring( in_info * handle);
static int  prepare_tpacket_socket(in_info* handle );
#endif 
static int config_radio_interface(const char device[]);
static int up_radio_interface(const char device[]);
static int down_radio_interface(const char device[]);
static int open_infd(const char device[]);
static int ind =0;
in_info handle[2];

#ifdef NON_PACKET_MMAP
u_int64_t timeval_to_int64(const struct timeval* tv)
{
  return (int64_t)(((u_int64_t)(*tv).tv_sec)* 1000000ULL + ((u_int64_t)(*tv).tv_usec));
}
#endif

static int config_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct iwreq    wrq;
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_name, device, IFNAMSIZ);
  wrq.u.mode = IW_MODE_MONITOR;
  if (0 > ioctl(sd, SIOCSIWMODE, &wrq)) {
    perror("ioctl(SIOCSIWMODE) \n");
    syslog(LOG_ERR, "ioctl(SIOCSIWMODE): %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

static int up_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  const int flags = IFF_UP|IFF_RUNNING|IFF_PROMISC;
  if (ifr.ifr_flags  == flags)
    return 0;
  ifr.ifr_flags = flags;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIFFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return -1;
  }  
  return 0;
}
static int down_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  if (0 == ifr.ifr_flags)
    return 0;
  ifr.ifr_flags = 0;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIWMODE)\n");
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  return 0;
}


static int open_infd(const char device[])
{
  int skbsz ;
  skbsz = 1U << 23 ; 
  int in_fd ;
  in_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (in_fd < 0) {
    perror("socket(PF_PACKET)\n");
    return -1;
  }
  struct ifreq ifr;
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  
  if (0 > ioctl(in_fd, SIOCGIFINDEX, &ifr)) {
    perror("ioctl(SIOGIFINDEX)\n");
    return -1;
  }
  //printf("the ifindex of device is %d\n",ifr.ifr_ifindex);
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family  = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol= htons(ETH_P_ALL);
  if (0 > bind(in_fd, (struct sockaddr *) &sll, sizeof(sll))) {
    perror("bind()\n");
    return -1;
  }
#ifdef NON_PACKET_MMAP 
  if (0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz, sizeof(skbsz))) {
    perror("setsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int skbsz_l = sizeof(skbsz);
  if (0 > getsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz,
		     (socklen_t*)&skbsz_l)) {
    perror("getsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int rcv_timeo = 600;
  struct timeval rto = { rcv_timeo, 0};
  if (rcv_timeo > 0 &&
      0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto))) {
    perror( "setsockopt(in_fd, SO_RCVTIMEO)\n");

    return -1;
  }
#endif
  return in_fd ;
}


int checkup(char * device){
  int in_fd ;
  if (down_radio_interface(device)){
    perror("down radio interface \n");
    return -1;
  }

  if (up_radio_interface(device)){
    perror("up radio interface \n");
    return -1;
  }
  
  if (config_radio_interface(device)){
    perror("config radio intereface ");
    return -1;
  }
  in_fd = open_infd(device);
  if(in_fd == -1){
    perror("Can't set socket option. Abort ");
    return -1;
 }
  memset(&handle[ind],'\0',sizeof(in_info));
	handle[ind].in_fd= in_fd ;	
#ifndef NON_PACKET_MMAP
  int retval =activate_mmap(&handle[ind]);
  if (retval != 1){
    fprintf(stderr, "Could not activate mmap \n");
    return -1;
  }
#endif   
  ind++;
  return in_fd;
}
int tp_drops[2] = {0,0};
int tp_packets[2] = {0,0};
int k_pkt_stats()
{
  int interf =0;
int stats_drops =0;
  for(interf =0; interf<2; interf++){
    struct tpacket_stats kstats;
    socklen_t sl = sizeof (struct tpacket_stats);
    if (0 != getsockopt(handle[interf].in_fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &sl)) {
      perror("getsockopt(PACKET_STATISTICS)\n");
      return 0;
    }
    if (0 == kstats.tp_drops)
      return 1;
    tp_drops[interf] = kstats.tp_drops ; 
    tp_packets[interf] = kstats.tp_packets ;  
    stats_drops =1 ;	 
    if(tp_drops[interf] >0) {
		fprintf( stderr, "#drops[%d] =%d \n",interf,tp_drops[interf] );
    }
    
#if 0
    // not to use.. cause overhead 
    struct timeval now; 
    struct timeval _tstamp;
    gettimeofday(&now, NULL);
    int delay = -1000;
    if (0 == ioctl(in_fd, SIOCGSTAMP, &_tstamp)) {
      delay = timeval_to_int64(&now) - timeval_to_int64(&_tstamp);
    } else {
      perror("ioctl(SIOCGTSTAMP)\n");
    }
#endif
  }

  if(stats_drops ==1 ){
					printf("writing into file \n");
    gzFile drops_handle = gzopen (PENDING_UPDATE_DROPS_FILENAME, "wb");
    if (!drops_handle) {
      perror("Could not open update drops file for writing\n");
      exit(1);
    }
    if (!gzprintf(drops_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
      perror("Error writing drops update\n");
      exit(1);
    }
    // write here 
    if(!gzprintf(drops_handle,"%d|%d|%d|%d\n", tp_drops[0], tp_packets[0], tp_drops[1],tp_drops[1])){
      perror("error writing the mac data zip file ");
      exit(1);
    }    
    gzclose(drops_handle);
    char update_drops_filename[FILENAME_MAX];
    snprintf(update_drops_filename,FILENAME_MAX,UPDATE_DROPS_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
    if (rename(PENDING_UPDATE_DROPS_FILENAME, update_drops_filename)) {
      perror("Could not stage drops update\n");
      exit(1);
    }
    stats_drops =0;
    tp_drops[0] =0;  tp_packets[0]=0; tp_drops[1]=0;tp_drops[1]=0;
  }

  return 1;
}

#ifndef NON_PACKET_MMAP

# ifdef TPACKET_HDRLEN
#  define HAVE_PACKET_RING 
#  ifdef TPACKET2_HDRLEN 
#   define HAVE_TPACKET2
#  else
#   define TPACKET_V1   0
#  endif
# endif  

#ifdef HAVE_PACKET_RING
#define RING_GET_FRAME(h) (((union thdr **)h->buffer)[h->offset])
#endif

int activate_mmap(in_info* handle ){
  int ret;
  // Attempt to allocate a buffer to hold the contents of one packet, for use by the oneshot callback.
  handle->snapshot=8000; // mpdu is 7k+ for n packets 
  handle->oneshot_buffer = malloc(handle->snapshot);
  if (handle->oneshot_buffer == NULL) {
    printf("can't allocate oneshot buffer: %s",strerror(errno));
    return -1;
  }

  if (handle->buffer_size == 0) {
  //TODO:  by default request 1M for the ring buffer 
  printf("setting buffer size 1MB\n");
  handle->buffer_size = 2*1024*1024;
  }else{
  printf("handle buffer already set = %d \n",handle->buffer_size);
  }
  
  ret = prepare_tpacket_socket(handle);
  if (ret != 1) {
    fprintf(stderr,"Can't prepare tpacket sockets  \n");
    free(handle->oneshot_buffer);
    return ret;
  }
  ret = create_ring(handle);
  if (ret != 1) {
    fprintf(stderr, "Can't create ring \n");
    free(handle->oneshot_buffer);
    return ret;
  }
  return 1;
}

static int prepare_tpacket_socket(in_info* handle)
{
  socklen_t len;
  int val;
  handle->tp_version = TPACKET_V1;
  handle->tp_hdrlen = sizeof(struct tpacket_hdr);

  // Probe whether kernel supports TPACKET_V2 
  val = TPACKET_V2;
  len = sizeof(val);
  if (getsockopt(handle->in_fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
    if (errno == ENOPROTOOPT){
      perror("Error: ENOPROTOOPT ; drive on \n");
      return 1;       // no - just drive on 
    }
    // Yes - treat as a failure. 
    perror("can't get TPACKET_V2 header len on packet socket\n");
    return -1;
  }
  handle->tp_hdrlen = val;
  val = TPACKET_V2;
  if (setsockopt(handle->in_fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0) {
    perror("can't activate TPACKET_V2 on packet socket\n");
    return -1 ;
  }
  handle->tp_version = TPACKET_V2;
  return 1;
}

static int create_ring(in_info *handle)
{
  unsigned i, j, frames_per_block;
  struct tpacket_req req;
  
  //TODO: Note that with large snapshot (say 64K) only a few frames  will be available in the ring even with pretty 
  //large ring size (and a lot of memory will be unused). The snap len should be carefully chosen to achive best performance 
  req.tp_frame_size = TPACKET_ALIGN(handle->snapshot + TPACKET_ALIGN(handle->tp_hdrlen) + sizeof(struct sockaddr_ll));
  req.tp_frame_nr = handle->buffer_size/req.tp_frame_size;

  req.tp_block_size = getpagesize();
  while (req.tp_block_size < req.tp_frame_size)
    req.tp_block_size <<= 1;
	
  frames_per_block = req.tp_block_size/req.tp_frame_size;
 retry:
  req.tp_block_nr = req.tp_frame_nr / frames_per_block;

  // req.tp_frame_nr is requested to match frames_per_block*req.tp_block_nr 
  req.tp_frame_nr = req.tp_block_nr * frames_per_block;

  if (setsockopt(handle->in_fd, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req))) {
    if ((errno == ENOMEM) && (req.tp_block_nr > 1)) {
      if (req.tp_frame_nr < 20)
	req.tp_frame_nr -= 1;
      else
	req.tp_frame_nr -= req.tp_frame_nr/20;
      goto retry;
    }
    if (errno == ENOPROTOOPT) {
     	perror("No support for ring buffer\n"); 
      return 0;
    }
    perror("Can't create rx ring on packet socket\n");
    return -1;
  }
  // memory map the rx ring 
  handle->mmapbuflen = req.tp_block_nr * req.tp_block_size;
  handle->mmapbuf = mmap(0, handle->mmapbuflen,PROT_READ|PROT_WRITE, MAP_SHARED, handle->in_fd, 0);
  if (handle->mmapbuf == MAP_FAILED) {
    perror("Can't mmap rx ring\n");
    destroy_ring(handle);
    return -1;
  }
  // allocate a ring for each frame header pointer
  handle->cc = req.tp_frame_nr;
  handle->buffer = malloc(handle->cc * sizeof(union thdr *));
  if (!handle->buffer) {
    printf("can't allocate ring of frame headers: %s", strerror(errno));
    destroy_ring(handle);
    return -1;
  }
  // fill the header ring with proper frame ptr
  handle->offset = 0;
  for (i=0; i<req.tp_block_nr; ++i) {
    void *base = &handle->mmapbuf[i*req.tp_block_size];
    for (j=0; j<frames_per_block; ++j, ++handle->offset) {
      RING_GET_FRAME(handle) = base;
      base += req.tp_frame_size;
    }
  }
  handle->bufsize = req.tp_frame_size;
  handle->offset = 0;
  printf("created ring with %d for interface %d \n", handle->bufsize, handle->in_fd );
  return 1;
}

// free all ring related resources
static void destroy_ring(in_info * handle )
{
  struct tpacket_req req;
  free(handle->oneshot_buffer);
	free(handle->buffer);	
  memset(&req, 0, sizeof(req));
  setsockopt(handle->in_fd, SOL_PACKET, PACKET_RX_RING,(void *) &req, sizeof(req));
  // if ring is mapped, unmap it
  if (handle->mmapbuf) {
    // do not test for mmap failure, as we can't recover from any error 
    munmap(handle->mmapbuf, handle->mmapbuflen);
    handle->mmapbuf = NULL;
  }
}

static inline union thdr * get_ring_frame(in_info *handle, int status)
{
  union thdr h;
  h.raw = RING_GET_FRAME(handle);
  switch (handle->tp_version) {
  case TPACKET_V1:
    if (status != (h.h1->tp_status ? TP_STATUS_USER :  TP_STATUS_KERNEL))
      return NULL;
    break;
  case TPACKET_V2:
    if (status != (h.h2->tp_status ? TP_STATUS_USER : TP_STATUS_KERNEL))
      return NULL;
    break;
  }
  return h.raw;
}

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

int read_mmap(in_info *handle, callback_handler callback, int interface ){
  int pkts = 0;
  char c;
  // wait for frames availability
  if (!get_ring_frame(handle, TP_STATUS_USER)) {
    struct pollfd pollinfo;
    int ret;
    printf("in !get ring frame \n");
    if(handle->in_fd ==10){
      printf("I got a fd 10\n");
      clean_interfaces();
      exit(1);
    }
    pollinfo.fd = handle->in_fd;
    pollinfo.events = POLLIN;
		printf("poll fd =%d \n ", pollinfo.fd);
    do {
      printf("in do loop\n");
      ret = poll(&pollinfo, 1,0); // set 0 for non blocking mode 
      if (ret < 0 && errno != EINTR) {
	perror("Can't poll on packet socket\n");
	return -1;
      } else if (ret > 0 &&
		 (pollinfo.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {	
	// There's some indication other than "you can read on this descriptor" on the descriptor.
	printf("ret is greater than 0 and pollrevents\n ");
	if (pollinfo.revents & (POLLHUP | POLLRDHUP)) {
	  fprintf(stderr,"Hangup on packet socket");
	  return -1;
	}
	if (pollinfo.revents & POLLERR) {	  
	  //  A recv() will give us the actual error code. XXX - make the socket non-blocking?	   
	  if (recv(handle->in_fd, &c, sizeof c, MSG_PEEK) != -1){
	    printf("before continue \n");
	    clean_interfaces();
	    exit(1);
	    continue;       // what, no error? 
	  }else{
	    printf("in else recv\n");
	  }
	  if (errno == ENETDOWN) {	    
	    // The device on which we're capturing went away.
	    perror("The interface went down\n");
	  } else {
	    perror("Error condition on packet socket\n");
	  }
	  return -1;
	}
	if (pollinfo.revents & POLLNVAL) {
	  printf("Invalid polling request on packet socket");
	  return -1;
	}
      }

    } while (ret < 0);
  }
  // non-positive values of max_packets are used to require all  packets currently available in the ring 
  int max_packets = -1; 
  while ((pkts < max_packets) || (max_packets <= 0)) {
    int run_bpf;
    struct sockaddr_ll *sll;
    pkthdr pkt_hdr;
    unsigned char *bp;
    union thdr h;
    unsigned int tp_len;
    unsigned int tp_mac;
    unsigned int tp_snaplen;
    unsigned int tp_sec;
    unsigned int tp_usec;
    h.raw = get_ring_frame(handle, TP_STATUS_USER);
    if (!h.raw){
      break;
		}
    switch (handle->tp_version) {
    case TPACKET_V1:
      tp_len     = h.h1->tp_len;
      tp_mac     = h.h1->tp_mac;
      tp_snaplen = h.h1->tp_snaplen;
      tp_sec     = h.h1->tp_sec;
      tp_usec    = h.h1->tp_usec;
      break;
    case TPACKET_V2:
      tp_len     = h.h2->tp_len;
      tp_mac     = h.h2->tp_mac;
      tp_snaplen = h.h2->tp_snaplen;
      tp_sec     = h.h2->tp_sec;
      tp_usec    = h.h2->tp_nsec / 1000;
      break;
    default:
      fprintf(stderr,"unsupported tpacket version %d \n", handle->tp_version);
      return -1;
    }
    // perform sanity check on internal offset. 
    if (tp_mac + tp_snaplen > handle->bufsize) {
      fprintf(stderr,"corrupted frame on kernel ring mac " "offset %d + caplen %d > frame len %d\n", tp_mac, tp_snaplen, handle->bufsize);
      return -1;
    }
    bp = (unsigned char*)h.raw + tp_mac;
    // Do checks based on packet direction.     
    sll = (void *)h.raw + TPACKET_ALIGN(handle->tp_hdrlen);
    // get required packet info from ring header
    pkt_hdr.ts.tv_sec = tp_sec;
    pkt_hdr.ts.tv_usec = tp_usec;
    pkt_hdr.caplen = tp_snaplen;
    pkt_hdr.len = tp_len;
    // no need for vlan stuff ! 
    if (handle->tp_version == TPACKET_V2 && h.h2->tp_vlan_tci &&	tp_snaplen >= 2 * ETH_ALEN) {
      struct vlan_tag *tag;
      bp -= VLAN_TAG_LEN;
      memmove(bp, bp + VLAN_TAG_LEN, 2 * ETH_ALEN);
      tag = (struct vlan_tag *)(bp + 2 * ETH_ALEN);
      tag->vlan_tpid = htons(ETH_P_8021Q);
      tag->vlan_tci = htons(h.h2->tp_vlan_tci);
      pkt_hdr.caplen += VLAN_TAG_LEN;
      pkt_hdr.len += VLAN_TAG_LEN;
    } 
     //The only way to tell the kernel to cut off the packet at a snapshot length is with a filter program;
     // if there's no filter program, the kernel won't cut the packet off.     
     // Trim the snapshot length to be no longer than the specified snapshot length.
     
    if (pkt_hdr.caplen > handle->snapshot)
      pkt_hdr.caplen = handle->snapshot;
    // pass the packet to the user 
    pkts++;
    callback(interface, &pkt_hdr, bp);
    handle->packets_read++;
  skip:
    // next packet 
    switch (handle->tp_version) {
    case TPACKET_V1:
      h.h1->tp_status = TP_STATUS_KERNEL;
      break;
    case TPACKET_V2:
      h.h2->tp_status = TP_STATUS_KERNEL;
      break;
    }
    if (++handle->offset >= handle->cc)
      handle->offset = 0;
  }
  return pkts;
}

int clean_interfaces(){
	int i ;
	for (i=0;i<2;i++){
		destroy_ring(&handle[i]);
		if(handle[i].oneshot_buffer!=NULL){
			free(handle[i].oneshot_buffer);
			handle[i].oneshot_buffer=NULL;
		}
	}

return 0 ;
}

#endif  
