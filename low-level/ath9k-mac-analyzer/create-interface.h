#ifndef _CREATE_INTERFACE_H_
#define _CREATE_INTERFACE_H_

#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include "td-util.h"
#define  NON_PACKET_MMAP

#ifndef NON_PACKET_MMAP
typedef struct {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
} pkthdr;

union thdr {
  struct tpacket_hdr      *h1;
  struct tpacket2_hdr     *h2;
  void                    *raw;
};
struct vlan_tag {
	 u_int16_t       vlan_tpid;              /* ETH_P_8021Q */
	 u_int16_t       vlan_tci;               /* VLAN TCI */
};
typedef void (*callback_handler)(int, const pkthdr *, const uchar *);
int read_mmap(in_info *, callback_handler callback, int interface);
int activate_mmap(in_info* handle );
int clean_interfaces();
#define VLAN_TAG_LEN    4
#endif


typedef struct  {
	int in_fd;
#ifndef NON_PACKET_MMAP
  uchar* oneshot_buffer ; 
  uchar *mmapbuf;    
  uchar * buffer;
  size_t mmapbuflen;  
  unsigned int tp_version;     /* version of tpacket_hdr for mmaped ring */
  unsigned int tp_hdrlen;      /* hdrlen of tpacket_hdr for mmaped ring */
  int buffer_size;
  int bufsize;
	int direction;
  int snapshot;
  int cc ;
	int timeout;
  int offset ; 
	u_int packets_read ; 
#endif
} in_info  ;
extern in_info handle[2];


int checkup(char* device) ;
u_int64_t timeval_to_int64(const struct  timeval *tv);
int k_pkt_stats();
extern int tp_drops[2] ;
extern int tp_packets[2];
extern int stats_drops; 	
#endif

