/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * iw.c                                                                        *
 *                                                                             *
 * DATE                                                                        *
 * 18/09/2012                                                                  *
 *                                                                             *
 * AUTHOR                                                                      *
 * atzeton - http://www.nullsecurity.net/                                      *
 *                                                                             *
 * LICENSE                                                                     *
 * GNU GPLv2, see COPYING                                                      *
 *                                                                             *
 ******************************************************************************/
 
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "hwk.h"

int8_t 
iw_get_txpower(char *devname)
{
	int32_t sockfd = socket(AF_PACKET, SOCK_RAW, 0);
	
    struct iwreq wrq;
    strncpy(wrq.ifr_name, devname, sizeof(devname));
    
    if( ioctl(sockfd, SIOCGIWTXPOW, &wrq) < 0) {
        return(-1);
    }
    
    return(wrq.u.txpower.value);
}


/* 2.4 Ghz frequence to channel */
int8_t 
iw_freq2channel(uint16_t freq) 
{
    freq = freq - 2407;
    return((int8_t)(freq/5));
}


uint16_t
iw_channel2freq(uint8_t channel)
{
    uint32_t freq = 2407 + channel*5;
    
    return(freq);
}


int8_t
iw_get_channel(char *devname)
{
	 int32_t sockfd = socket(AF_PACKET, SOCK_RAW, 0);
	
	
    struct iwreq wrq;
    strncpy(wrq.ifr_name, devname, sizeof(devname));
    
    if( ioctl(sockfd, SIOCGIWFREQ, &wrq) < 0) {
        return(-1);
    }
    
    return(iw_freq2channel(wrq.u.freq.m));
}


int8_t 
iw_set_mtu(char *dev, uint16_t mtu)
{
	int32_t sockfd = 0; 
	struct ifreq	*ifr = calloc(1, sizeof(struct ifreq));
	
	sockfd = socket(AF_PACKET, SOCK_RAW, 0);
	if( sockfd < 0) {
		__WARNING("creating set_mtu socket failed");
    }
    
    ifr->ifr_mtu = mtu;
    strncpy(ifr->ifr_name, dev, strlen(dev));    
    
    if( ioctl(sockfd, SIOCSIFMTU, (caddr_t)ifr) < 0) {
		__WARNING("set_mtu ioctl SIOCSIFMTU failed");
	}
    
    free(ifr);
    close(sockfd);
   
    return(0);
	
}


int8_t 
iw_set_channel(char *dev, int8_t channel) 
{
	int32_t sockfd = socket(AF_PACKET, SOCK_RAW, 0);
	
    if( channel == 0) {
        return(0);
    }
    
    struct iwreq *wrq = calloc(1, sizeof(struct iwreq));
    strncpy(wrq->ifr_name, dev, 14);
    
    wrq->u.freq.m = channel;

    if( ioctl(sockfd, SIOCSIWFREQ, wrq) < 0) {
		return(-1);
    }
    
    free(wrq);
    
    close(sockfd);
    
    return(0);
}


    
