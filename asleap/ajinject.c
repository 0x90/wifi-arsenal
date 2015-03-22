/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: ajinject.c,v 1.4 2004/09/30 11:41:35 jwright Exp $
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
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

/* Much of this code is taken form the AirJack project and associated tools */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap-bpf.h>
#include <time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include "ajinject.h"
#include "airjack.h"

/* aj_setnonblock accepts the airjack_data structure with an open socket, and a
   flag to specify whether or not to go nonblock. 
   This code coincidentally resembles similar libpcap functions.  No, really. */
int aj_setnonblock(char *ifname, int nonblock) {

    int fdflags;
    int sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    fdflags = fcntl(sock, F_GETFL, 0);
    if (fdflags == -1) {
                perror("fcntl[F_GETFL]");
        close(sock);
        return (-1);
    }
    if (nonblock)
        fdflags |= O_NONBLOCK;
    else
        fdflags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, fdflags) == -1) {
                perror("fcntl[F_SETFL]");
        close(sock);
        return (-1);
    }
    close(sock);
    return (0);
}

/* aj_getnonblock accepts the airjack_data structure with an open socket, and
   returns whether the interface is currently in blocking (0) or nonblock (1)
   mode.  aj_getnonblock returns a 0 or 1, respectively. */
int aj_getnonblock(char *ifname) {

    int flags, mode, sock;


    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl[F_GETFL]");
        close(sock);
        return(-1);
    }

    mode = flags & O_NONBLOCK;
    close(sock);
    return(mode);

}

/* aj_setmonitor sets or disables RFMON mode for AirJack interfaces */
int aj_setmonitor(char *ifname, int rfmonset) {

    struct aj_config ajconf;
    struct ifreq req;
    int sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    ajconf.monitor = rfmonset;

    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    return(0);

}


/* aj_setmode sets the operating mode for  AirJack interfaces */
int aj_setmode(char *ifname, int mode) {

    struct aj_config ajconf;
    struct ifreq req;
    int    sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    ajconf.mode = mode;

    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    close(sock); 
    return(0);

}

/* aj_setchannel changes the airjack card to the specified channel */
int aj_setchannel(char *ifname, int channel) {

    struct aj_config ajconf;
    struct ifreq req;
    int    sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    ajconf.channel = channel;

    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    close(sock); 
    return(0);

}


int aj_setessid(char *ifname, char *essid, int len) {

    struct aj_config ajconf;
    struct ifreq req;
    int sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    strncpy(ajconf.essid + 1, essid, len);
    ajconf.essid[0] = len;

    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    close(sock); 
    return(0);
}


int aj_setmac(char *ifname, u8 *mac) {

    struct aj_config ajconf;
    struct ifreq req;
    int    sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    memcpy(ajconf.ownmac, mac, 6); 

    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }

    close(sock); 
    return(0);
}


/* aj_xmitframe accepts a 8-bit array of data, and a number of bytes to send
   with an open socket.  If we are blocking on the socket, just transmit the
   data and return 0 is send returns the same number of bytes sent.  If we are
   in nonblock mode, perform a select on the socket and if it is available for
   writing, send the data.  If it is not available for writing, we loop and 
   keep trying to send until select returns the socket as available.  Note that
   this behavior is different from the aj_recvframe function that will
   immediately return of select indicates that the socket is not ready to
   deliver a frame. */
int aj_xmitframe(char *ifname, u8 *xmit, int len) {

    int xmitlen = 0;
    int n = 0, sock;
    struct timeval tv;
    fd_set saved_set, wset;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    if (aj_getnonblock(ifname) == 0) {

        /* We are blocking, just transmit the data */
        xmitlen = write(sock, &xmit, len);

    } else {
        /* We are nonblock, perform a select on the socket */

        FD_ZERO(&saved_set);
        FD_SET(sock, &saved_set);
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        while(1) {

            wset = saved_set;
            n = select(sock+1, NULL, &wset, NULL, &tv);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    /* debug */
                    printf("write would block: %d.  continuing.\n", errno);
                    continue;
                } else {
                    fprintf(stderr, "select on write socket returned %d.\n", 
                        errno);
                    return(-1);
                }
            } else if (n == 0) {
                /* timeout expired before a filehandle was populated.  
                   try again. */
                continue;
            } else {
                printf("select returned %d.\n", n);
                /* select returned > 0, transmit the packet */
                printf("before send errno: %d\n", errno);
                xmitlen = write(sock, &xmit, len);
                printf("after send errno: %d\n", errno);
                printf("send returned %d.\n", xmitlen);
                break;
            }
    
        } /* end while(1) */

    }

    close(sock); 
    if (len == xmitlen) {
        return(0);
    } else {
        fprintf(stderr, "send returned %d, not %d bytes.\n", xmitlen, len);
        perror("write");
        return(-1);
    }

}

/* aj_recvframe accepts an 8-byte character array of data, with a length of the
   packet to transmit with the socket in the airjack_data struct.  aj_recvframe
   will test to see if we are currently blocking on the interface.  If we are
   blocking, we simply wait until the packet is received with recv().  If we are
   in nonblock mode, we select on the socket using a fixed timeout parameter,
   and if we don't get any data within that time, we return 1.  An error will
   return -1, success returns 0.
   TODO: Add a timeval struct to the ifname struct for use in the select() on
   the socket for receiving data, instead of a fixed timeout duration. 
   TODO: Write this function. */
int aj_recvframe(char *ifname, u8 *buf, int len) {

    return(-1);

}

int aj_ifupdown(char *ifname, int devup) {

    struct ifreq ifr;
    int    sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Populate the ifr struct with the airjack interface name */
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    /* Get current flag information from the interface */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCGIFFLAGS]");
        close(sock);
        return(1);
    }

    if (devup) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    /* Set the flag information */
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCSIFFLAGS]");
        close(sock);
        return(1);
    }

    return(0);

}

/* aj_getsocket accepts the AirJack interface char * and 
   return a socket, or -1 on error.  This is cribbed right from essid_jack.c,
   thanks Abaddon. */
int aj_getsocket(char *ifname) {

    struct sockaddr_ll	addr;
    struct ifreq	req;
    struct aj_config	aj_conf;
    int    sock;


    /* open the link layer socket */
    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        return(-1);
    }

    /* get the interface index */
    memset(&req, 0, sizeof(struct ifreq));
    memset(&aj_conf, 0, sizeof(struct aj_config));
    strcpy(req.ifr_name, ifname);

    if(ioctl(sock, SIOCGIFINDEX, &req) < 0) {
        close(sock);
        return(-1);
    }

    /* bind the socket to the interface */
    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_ifindex = req.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_family = AF_PACKET;
    if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0) {
        close(sock);
        return(-1);
    }

    return(sock);
}

