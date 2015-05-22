# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <string.h>
# include <arpa/inet.h>

void error (const char * msg) {fprintf(stderr,"\x1b[31m[ ! ] %s\n\x1b[0m",msg);}
void info  (const char * msg) {fprintf(stdout,"\x1b[34m[ + ] %s\n\x1b[0m",msg);}
void debug (const char * msg) {fprintf(stdout,"\x1b[36m[ > ] %s\n\x1b[0m",msg);}

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct mac { unsigned char x[6]; } mac;
typedef struct oui { unsigned char x[3]; } oui;

typedef struct pkt_hdr_80211_s {
  uint8_t type; /* lol type/subtype stuff didntread.gif */
  uint8_t flags;
  uint16_t duration;
  mac dst_mac;
} pkt_hdr_80211_t;

typedef struct pkt_hdr_80211_sender_s {
  mac src_mac;
  mac bss_mac;
  uint16_t sequence;
} pkt_hdr_80211_sender_t;

typedef struct llc_s {
  uint8_t dsap;
  uint8_t snap;
  uint8_t control;
  oui oui;
  uint16_t type;
} llc_t;

typedef struct auth802_s {
  uint8_t version;
  uint8_t type;
  uint16_t length;
} auth802_t;

typedef struct eap_hdr_s {
  uint8_t type;
  uint8_t id;
  uint16_t size;
} eap_hdr_t;

void debug_info_file_header( pcap_hdr_t * hdr ) {
  debug("cap header content :");
  printf("%30s %8x\n","magic number"             , hdr->magic_number);  
  printf("%30s %8x\n","major version number"     , hdr->version_major); 
  printf("%30s %8x\n","minor version number"     , hdr->version_minor); 
  printf("%30s %8x\n","GMT to local correction"  , hdr->thiszone);       
  printf("%30s %8x\n","accuracy of timestamps"   , hdr->sigfigs);       
  printf("%30s %8x\n","lenght of captured packets", hdr->snaplen);       
  printf("%30s %8x\n","data link type"            , hdr->network);       
}

void debug_info_packet_header (pcaprec_hdr_t * pkt_hdr, unsigned int index) {
  if (pkt_hdr->incl_len == pkt_hdr->orig_len) {
    printf("\x1b[36m[ packet %3d ]\x1b[0m %x.%ds %3d ",
      index,
      pkt_hdr->ts_sec,
      pkt_hdr->ts_usec,
      pkt_hdr->incl_len);
  } else {
    printf("\x1b[36m[ packet %3d ]\x1b[0m %x.%ds %3d (got %d) ",
      index,
      pkt_hdr->ts_sec,
      pkt_hdr->ts_usec,
      pkt_hdr->orig_len,
      pkt_hdr->incl_len);
  }
}

void print_mac(mac * mac) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x",
      mac->x[0],
      mac->x[1],
      mac->x[2],
      mac->x[3],
      mac->x[4],
      mac->x[5]
      );
}
void debug_info_packet_header_80211( pkt_hdr_80211_t * h ) {
  uint8_t type = 0;
  type = h->type & 0xff;
  type = ((type & 0xc) << 2) + (type >> 4);

  printf("\x1b[36m[ type %02x ]\x1b[0m > ",type);
  print_mac(&h->dst_mac);
}

void debug_info_packet_header_80211_sender ( pkt_hdr_80211_sender_t * h ) {
  printf(" < ");
  print_mac(&h->src_mac);
  printf(" bss ");
  print_mac(&h->bss_mac);
  printf(" %4x",h->sequence);
}

void debug_info_llc( llc_t * llc ){
  printf("%02x %02x %02x",llc->dsap,llc->snap,llc->control);
  printf(" type %04x",llc->type);
}

void debug_info_8021_auth ( auth802_t * h ){
  switch (h->type) {
    case 0: printf(" %d bytes",h->length); break;
    case 1: printf(" \x1b[35mEAP Start\x1b[0m"); break;
    case 2: printf(" Unkown EAP 2"); break;
    case 3: printf(" \x1b[32m\x1b[1mKEY §§\x1b[0m %d bytes",h->length); break;
    default: printf(" Unkown EAP %x",h->type);
  }
}

void debug_info_eap_header ( eap_hdr_t * h ) {
  printf(" EAP");
  switch (h->type) {
    case 1: printf(" \x1b[34mRequest \x1b[0m"); break;
    case 2: printf(" \x1b[32mResponse\x1b[0m"); break;
    case 4: printf(" \x1b[31mFailure \x1b[0m"); break;
    default: ;
  }
  printf(" %d %d",h->id,h->size);
}

int main(int argc, char * argv []) {
  FILE * fp = NULL;
  size_t read_size = 0;
  pcap_hdr_t cap_header;
  pcaprec_hdr_t packet_header;
  unsigned int index = 1;
  pkt_hdr_80211_t packet_header_80211;
  pkt_hdr_80211_sender_t packet_header_80211_sender;
  llc_t packet_header_llc;
  auth802_t packet_header_8021_authentication;
  eap_hdr_t packet_eap_header;
  long next_packet = 0;
  unsigned int debug = 0;

  /* 1. read input .cap */
  if (argc < 2) {
    info("Usage : ./pixie <capture.cap>");
    return 1;
  } else {
    if (strncmp((const char *)(((unsigned long int)argv[1]) + (strlen(argv[1]) - 4)), (const char *) ".cap", 4) == 0) {
      fp = fopen(argv[1],"r");
      if (fp == NULL) {
        error("fopen( .cap ); failed !");
        return 1;
      }
    } else {
      error("Extension should be .cap");
      info("Usage : ./pixie <capture.cap>");
      return 1;
    }
  }
  
  if (argc > 2) {
    if (strcmp(argv[2],"debug") == 0) {
      debug = 1;
    } else {
      debug = 0;
    }
  }

  /* 2.1 read .cap header */
  read_size = fread(&cap_header,sizeof(pcap_hdr_t),1,fp);
  if (read_size != 1) {
    error("Read error, aborting.");
    fclose(fp);
    return 1;
  }
  if (debug) {debug_info_file_header(&cap_header);}

  if (cap_header.network != 0x69) {
    error(".cap file is not Wi-Fi !");
    printf("Type : %02x\n",cap_header.network);
    fclose(fp);
    return 1;
  }
  /* 2. filter LLC/EAP/WPS packets */
  while (1) {
    /* 2.1 read header*/
    fread(&packet_header,sizeof(pcaprec_hdr_t),1,fp);
    if (feof(fp)) {break;}
    next_packet = packet_header.incl_len + ftell(fp);
    if (debug) {debug_info_packet_header (&packet_header, index);}
    /* read 802.11 header */
    fread(&packet_header_80211,sizeof(pkt_hdr_80211_t),1,fp);
    if (feof(fp)) {break;}

    /* It may be a retransmission, we don't care */
    if (packet_header_80211.flags == 0x08) {
      if (debug) {printf("\x1b[35mretransmission");}
    } else {
      /* It may be a lot of stuff we don't even want to know */
      switch (packet_header_80211.type) {
        case 0xd4: if (debug) {printf("\x1b[35mack");}  break;
        case 0x50: if (debug) {printf("\x1b[31mresponse");}        break;
        case 0x40: if (debug) {printf("\x1b[35mprobe");} break; /* todo, maybe, ssid printf */
        case 0xc4: if (debug) {printf("\x1b[35mclear to send\x1b[0m");} break;
        case 0x80: if (debug) {printf("\x1b[36mbeacon\x1b[0m");} break; /* todo, maybe print info */
        case 0x00: if (debug) {printf("\x1b[36massociation \x1b[32mrequest\x1b[0m");} break; /* todo, maybe print info */
        case 0x10: if (debug) {printf("\x1b[36massociation \x1b[31mresponse\x1b[0m");} break; /* todo, maybe print info */
        case 0xb0: if (debug) {printf("\x1b[32mauth\x1b[0m");}
        default :
          if (debug) {debug_info_packet_header_80211(&packet_header_80211);}
  
          /* 2.2 it may contain info about sender */
          if ((packet_header_80211.type & 4) == 0) {
            fread(&packet_header_80211_sender,sizeof(pkt_hdr_80211_sender_t),1,fp);
            if (feof(fp)) {break;}
            if (debug) {debug_info_packet_header_80211_sender(&packet_header_80211_sender);}

            /* It can be a data frame :D */
            if (packet_header_80211.type == 8) {
              /* read LLC */
              fread(&packet_header_llc,sizeof(llc_t),1,fp);
              if (feof(fp)) {break;}
              // debug_info_llc(&packet_header_llc);
              // todo : endianness :)
              if (ntohs(packet_header_llc.type) == 0x888e) {
                // if (debug) {printf(" \x1b[32m\x1b[1mauthentication :D");}
                fread(&packet_header_8021_authentication,sizeof(auth802_t),1,fp);
                if (feof(fp)) {break;}
                if (debug) {debug_info_8021_auth(&packet_header_8021_authentication);}
                fread(&packet_eap_header,sizeof(eap_hdr_t),1,fp);
                if (feof(fp)) {break;}
                if (debug) {debug_info_eap_header(&packet_eap_header);}
              }
            }
          }
        }
    }

    if (debug) {printf("\x1b[0m\n");}


    /* then go to next packet */
    if (fseek(fp,next_packet,SEEK_SET) != 0) {
      error("seek failed, file probably broken.");
      fclose(fp);
      return 2;
    }
    index += 1;
  }

  /* 3. close file*/
  fclose(fp);
  return 0;
}
