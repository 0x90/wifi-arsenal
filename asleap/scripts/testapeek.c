/*
 * testapeek - read through Airopeek capture files
 *
 * Copyright (c) 2003, Joshua Wright <Joshua.Wright@jwu.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * testapeek is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * $Id: testapeek.c,v 1.2 2003/11/24 22:31:34 jwright Exp $
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <net/if.h>
#include "../common.h"

#define max2unix 2082844800u


/* This program reads through the specified AiroPeek file to verify the packet
   lengths, written as a mechanism to troubleshoot why I'm not getting the
   correct packet sizes. */


/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) */
void lamont_hdump(unsigned char *bp, unsigned int length) {

  /* stolen from tcpdump, then kludged extensively */

  static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

  const unsigned short *sp;
  const unsigned char *ap;
  unsigned int i, j;
  int nshorts, nshorts2;
  int padding;

  printf("\n\t");
  padding = 0;
  sp = (unsigned short *)bp;
  ap = (unsigned char *)bp;
  nshorts = (unsigned int) length / sizeof(unsigned short);
  nshorts2 = (unsigned int) length / sizeof(unsigned short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      printf(" %04x", ntohs(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        printf(" %02x  ", *(unsigned char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        printf("     ");
      }
      if (!padding) printf("     ");
    }
    printf("  ");

    while (--nshorts2 >= 0) {
      printf("%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        printf("\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        printf("%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    printf(" %02x", *(unsigned char *)sp);
    printf("                                       %c", asciify[*ap]);
  }
  printf("\n");
}

/* Find the string "pkts" in the data file, searching byte by byte from the
   current file offset.  Assumes fp is an open file handle. */
int find_pktsdelim(FILE *fp) {

    unsigned long pktsdelim = 0;
    unsigned long pktsconst = 0;

    pktsconst = PKTS_HEADER;

    while(fread(&pktsdelim, 1, 1, fp) == 1) {

        if (pktsdelim == pktsconst) 
            return(0);

        pktsdelim = pktsdelim << 8;
    }

    /* If we got here, we didn't find the offset, return 1 */
    return(1);
}


/* Determine the packet capture file type - if the file passed to us is one
   of the packet types we understand.  Return the file type as #define'd in 
   asleap.h, negative on error. */
int test_filetype(char *filename) {
    struct apeekl_master_h masterh;
    struct apeekl_secondary_h secondh;
    struct apeekx_pkts_h pktsh;
    struct stat pcapstat;
    FILE   *fp;
    long int magictype = 0, pktsdelim = 0;
    int filetype = 0;

    memset(&masterh, 0, sizeof(masterh));
    memset(&secondh, 0, sizeof(secondh));
    memset(&pktsh, 0, sizeof(pktsh));
    memset(&pcapstat, 0, sizeof(pcapstat));

    /* Open the file and determine the file type.  Some files have a magic
       number in the first 4 bytes of the file that we can use, others do
       not */

    /* Make sure our filename is not null */
    if (strlen(filename) < 1) {
        fprintf(stderr, "Invalid filename.\n");
        return(-1);
    }

    /* Determine file size, return error if smaller than our minimum packet
       size */
    if (stat(filename, &pcapstat) < 0) {
        perror("Unable to stat the capture file");
        return(-2);
    }

    if (pcapstat.st_size < sizeof(struct ieee80211)) {
        fprintf(stderr, "File (%s) is too small: %d bytes.\n", filename,
            pcapstat.st_size);
        return(-2);
    }

    /* Open the file, read the first 4 bytes for magic number */
    if ((fp = fopen(filename, "r")) == NULL) {
        perror("Unable to open pcap file");
        return(-3);
    }

    if (fread(&magictype, sizeof(magictype), 1, fp) < 1) {
        fclose(fp);
        perror("Unable to read from pcap file");
        return(-4);
    }

    /* Test for file formats based on the first 4 bytes. */
    switch(magictype) {
        case LEPCAP_MAGIC_NUM:
            /* little endian libpcap file */
            filetype = LIBPCAP_OFFLINE_PCAP;
            break;
        case BEPCAP_MAGIC_NUM:
            /* big endian libpcap file */
            filetype = LIBPCAP_OFFLINE_PCAP;
            break;
        case APEEKX_MAGIC_NUM:
            /* Airopeek 2.X (file version 9) capture file (XML'ish) */
            filetype = APEEK_XML_OFFLINE_PCAP;
            break;
        default:
            break;
    }

    /* 
     * If we have gotten here, we need to test for other file formats that
     * don't have magic number information in the first 4 bytes of the header. 
     */

    if (filetype == 0) {
        /* We didn't set filetype based on magic number information.  Continue
           checking the file formats. */

        /* Test for legacy Airopeek file format */
    
        /* Go back to the beginning of the file */
        rewind(fp);
    
        /* Get the master header information */
        if ((fread(&masterh, sizeof(masterh), 1, fp)) != 1) {
            fclose(fp);
            perror("fread");
            return(-4);
        }
    
        /* Get the secondary header information */
        if ((fread(&secondh, sizeof(secondh), 1, fp)) != 1) {
            fclose(fp);
            perror("fread");
            return(-4);
        }
    
        secondh.physmedium = ntohl(secondh.physmedium);
    
        if (masterh.version == MASTERH_VERSION &&
            masterh.status == MASTERH_STATUS &&
            secondh.physmedium == SECONDH_PHYSMEDIUM) {
            /* Looks like a legacy AiroPeek file */
            filetype = APEEK_LEGACY_OFFLINE_PCAP;
        }
    
        /* Testing for additional files that do not have magic number
           information should go here. */
    }

    fclose(fp);

    /* If all the tests fail, filetype should still be 0, indicating an
       unrecognized file. */
    return(filetype);

}

void safe_close(FILE *fp, int ret) {
    if (fp != NULL) {
        fclose(fp);
    }
    exit(ret);
}
    


int main(int argc, char *argv[]) {

    FILE   *apeekfile;
    struct apeekl_rec_h apeeklprec;
    struct apeekl_master_h masterh;
    struct apeekl_secondary_h secondh;
    struct apeekx_rec_h apeekxprec;
    struct apeekx_pkts_h apeekpktsh;
    unsigned long long int usecs;
    struct timeval ptime;
    int    filetype=0, recnum=0, packetlen, freadret, packetcount=0;
    unsigned char packet[2314];


    if (argc < 2) {

        printf("testapeek: Report information about the specified AiroPeek"
               " file.\n");
        printf("    usage: %s filename.apc\n", argv[0]);
        exit(1);
    }

    memset(&masterh, 0, sizeof(masterh));
    memset(&secondh, 0, sizeof(secondh));
    memset(&apeeklprec, 0, sizeof(apeeklprec));
    memset(&apeekxprec, 0, sizeof(apeekxprec));
    memset(&apeekpktsh, 0, sizeof(apeekpktsh));

    /* Get file type */
    filetype = test_filetype(argv[1]);
    if (filetype < 0) {
        fprintf(stderr, "Error reading capture file.\n");
        exit(1);
    }
    if (filetype == 0) {
        fprintf(stderr, "Unable to determine file type.\n");
        exit(1);
    }

    switch(filetype) {
        case APEEK_LEGACY_OFFLINE_PCAP:
            printf("Recognized a legacy AiroPeek file.\n");
            break;
        case APEEK_XML_OFFLINE_PCAP:
            printf("Recognized an AiroPeek file.\n");
            break;
        default:
            fprintf(stderr, "Not a supported file type.\n");
            fprintf(stderr, "This program only works with Airopeek files.\n");
            exit(1);
            break;
    }


    if ((apeekfile = fopen(argv[1], "r")) == NULL) {
        perror("fopen");
        exit(1);
    }

    /* Process the files according to the file type */

    if (filetype == APEEK_LEGACY_OFFLINE_PCAP) {

        /* Get the master header information */
        if ((fread(&masterh, sizeof(masterh), 1, apeekfile)) != 1) {
            perror("fread");
            exit(1);
        }
    
        /* Get the secondary header information */
        if ((fread(&secondh, sizeof(secondh), 1, apeekfile)) != 1) {
            perror("fread");
            exit(1);
        }
    
        /* Switch byte ordering */
        secondh.filelength = ntohl(secondh.filelength);
        secondh.numpackets = ntohl(secondh.numpackets);
        secondh.timedate = ntohl(secondh.timedate);
        secondh.timestart = ntohl(secondh.timestart);
        secondh.timestop = ntohl(secondh.timestop);
    
        printf("Master Header Information:\n");
        printf("  Version of file is:       %d\n", masterh.version);
        printf("  Status number of file is: %d\n", masterh.status);
    
        printf("Secondary Header Information:\n");
        printf("  File length is:           %ld\n", secondh.filelength);
        printf("  Number of packets is:     %ld\n", secondh.numpackets);
        printf("  TimeDate is:              %ld\n", secondh.timedate);
        printf("  TimeStart is:             %ld\n", secondh.timestart);
        printf("  TimeStop is:              %ld\n", secondh.timestop);
        printf("  Media Type is:            %08x\n", secondh.mediatype);
        printf("  Physical Medium is:       %08x\n", secondh.physmedium);
        printf("  Application version is:   %08x\n", secondh.appver);
        printf("  Link speed is:            %08x\n", secondh.linkspeed);
    
        printf("\nPrinting per-packet statistics:\n");
    
        while (!feof(apeekfile)) {
    
            recnum++;
    
            /* Populate the per-packet header */
            memset(&apeeklprec, 0, sizeof(apeeklprec));
            freadret = fread(&apeeklprec, sizeof(apeeklprec), 1, apeekfile);
            if (freadret == 0) {
                printf("Reached EOF.\n");
                break;
            }
            apeeklprec.protonum = ntohs(apeeklprec.protonum);
            apeeklprec.length = ntohs(apeeklprec.length);
            apeeklprec.slice_length = ntohs(apeeklprec.slice_length);
            /* Calc packet len, read payload */
            if (apeeklprec.slice_length)
                packetlen = apeeklprec.slice_length;
            else
                packetlen = apeeklprec.length;
    
            /* Packet length includes 4 bytes I put in the previous header, 
               subtract */
            packetlen = packetlen - 4; 
     
            /* Round up packet size to an even number */
            if (packetlen % 2)
                packetlen++;
     
            memset(&packet, 0, sizeof(packet));
     
            if (packetlen < sizeof(packet)) {
                fread(&packet, packetlen, 1, apeekfile);
            } else {
                fprintf(stderr, "Packet length (%d) is greater than max packet "
                    "size (%d).\n", packetlen, sizeof(packet));
                fclose(apeekfile);
                exit(1);
            }
     
            printf("  Packet %d:\n", recnum);
            printf("    ProtoNum:        %d\n", apeeklprec.protonum);
            printf("    Length:          %d\n", apeeklprec.length);
            printf("    Slice Length:    %d\n", apeeklprec.slice_length);
            printf("    Flags:           0x%02x\n", apeeklprec.flags);
            printf("    Status:          0x%02X\n", apeeklprec.status);
            printf("    Timestamp Upper: 0x%08x\n", apeeklprec.timestamp_upper);
            printf("    Timestamp Lower: 0x%08x\n", apeeklprec.timestamp_lower);
            printf("    Data Rate:       %d Mbps\n", (apeeklprec.data_rate/2));
            printf("    Channel:         %d\n", apeeklprec.channel);
            printf("    Signal Level:    %d%\n", apeeklprec.signal_level);
            printf("    Packet Dump:\n");
            lamont_hdump(packet, packetlen);
            printf("\n\n");

        }

    }

    if (filetype == APEEK_XML_OFFLINE_PCAP) {

        /* The payload for packets in the AiroPeek 2.X file format follows the
           string "pkts" + 8 bytes of NULL.  The minimum offset for this
           information is defined with APEEKX_MIN_PKTS_OFFSET. */
        if (fseek(apeekfile, APEEKX_MIN_PKTS_OFFSET, SEEK_SET) < 0) {
            perror("Unable to seek to data offset");
            safe_close(apeekfile, 1);
        }

        if (find_pktsdelim(apeekfile) != 0) {
            fprintf(stderr, "Unable to identify offset for packet payload.\n");
            safe_close(apeekfile, 1);
        }

        if (fread(&apeekpktsh, sizeof(apeekpktsh), 1, apeekfile) < 1) {
            perror("fread");
            safe_close(apeekfile, 1);
        }

        /* Read through the packets in the file */
        while(fread(&apeekxprec, sizeof(apeekxprec), 1, apeekfile) == 1) {

            packetcount++;
            printf("  Packet %d:\n", packetcount);
            printf("    Length 1:        %d\n", apeekxprec.length1);
            printf("    Length 2:        %d\n", apeekxprec.length2);
            printf("    Timestamp Upper: 0x%04x\n", apeekxprec.timestamp_upper);
            printf("    Timestamp Lower: 0x%04x\n", apeekxprec.timestamp_lower);
            printf("    Data Rate:       %d Mbps\n", (apeekxprec.data_rate/2));
            printf("    Channel:         %d\n", apeekxprec.channel);
            printf("    Signal Level:    %d%\n", 
                apeekxprec.signal_level_percent);
            printf("    Signal Level:    %ddBm\n", 
                apeekxprec.signal_level_dbm);

            memset(packet, 0, sizeof(packet));
            fread(packet, apeekxprec.length1, 1, apeekfile);
            lamont_hdump(packet, apeekxprec.length1);
            printf("\n");

        }

    }

    /* Exit with return value 0 */
    safe_close(apeekfile, 0);

}
