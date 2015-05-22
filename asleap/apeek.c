/*
 * asleap - actively recover weak LEAP passwords.  Pronounced "asleep".
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: apeek.c,v 1.5 2004/07/31 02:38:15 jwright Exp $
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

/* Code to handle reading from packet capture files, Airopeek legacy, Airopeek
   2.X and later and minimal code to determine libpcap files. */

#include <string.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>

#ifdef _LINUX
#include <sys/types.h>
#include <linux/if.h>
#else
#define IFNAMSIZ 16
#endif

#include "asleap.h"
#include "apeek.h"

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
    long int magictype = 0;
    int filetype = 0, pcapfilesize = 0, pcapdatalink = 0;

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
        pcapfilesize = pcapstat.st_size;
        fprintf(stderr, "File (%s) is too small: %d bytes.\n", filename,
            pcapfilesize);
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
        case BEPCAP_MAGIC_NUM:
    	    pcapdatalink = get_pcapdatalink(filename);
    	    if (pcapdatalink == DLT_IEEE802_11) {
    		    filetype = LPCAP_DLTRFMON_PCAP;
    	    } else if (pcapdatalink == DLT_EN10MB) {
    		    filetype = LPCAP_DLTETH_PCAP;
            } else if (pcapdatalink == DLT_NULL) {
                filetype = LPCAP_DLTNULL_PCAP;
    	    } else if (pcapdatalink == DLT_TZSP) {
    	        filetype = LPCAP_DLTTZSP_PCAP;
    		} else {
    		    fprintf(stderr, "Unknown pcap file type: %d\n", pcapdatalink);
    		    return(-1);
    	    }
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

/* Returns the supplied pcap capture file data link type */
int get_pcapdatalink(char *filename) {

    pcap_t *p;
    int    datalink = 0;
    char   errbuf[PCAP_ERRBUF_SIZE];

    p = pcap_open_offline(filename, errbuf);

    if (p == NULL) {
	return(-1);
    }

    datalink = pcap_datalink(p);
    pcap_close(p);
    return(datalink);
}
