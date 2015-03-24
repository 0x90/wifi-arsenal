/*
 This file is part of Diffprobe.

 Diffprobe is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 Diffprobe is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with pathload; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*-------------------------------------------------------------
   Diffprobe : Detecting traffic discrimination mechanisms.
   Authors   : Partha Kanuparthy     (partha@cc.gatech.edu)
               Constantinos Dovrolis (dovrolis@cc.gatech.edu)
   Release  : Ver 0.1
---------------------------------------------------------------*/

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "packet.h"
#include "diffprobe.h"


struct timeval prober_packet_gap(struct timeval y, struct timeval x);
void prober_swait(struct timeval tv, double sleepRes);
void prober_sbusywait(struct timeval tv);

int mflowSender(int tcpsock, int udpsock, struct sockaddr_in *from, 
		double capacity, double sleepRes, double *recvrate)
{
	pmflowstart startpkt;
	pmflowstartack ackpkt;
	pmflowend endpkt;
	pprobe probepkt;
	struct timeval gapts, gapts2, startts, endts, diffts, sendts;
	char buf[2000];
	int ret = 0;
	int duration = 0;
	double gap = 0;
	fd_set readset;
	struct timeval tout;
	int maxfd = tcpsock + 1;
	unsigned int fromlen = sizeof(struct sockaddr_in);
	unsigned long seq = 0, seq1 = 0;

	startpkt.header.ptype = P_MEASFLOW_START;
	startpkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&startpkt,
			sizeof(struct _mflowstart));
	if(ret == -1)
	{
		fprintf(stderr, "error writing to server: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _mflowstartack));
	if(ret == -1)
	{
		fprintf(stderr, "error reading from client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_MEASFLOW_START_ACK)
	{
		fprintf(stderr, "Bad start message!\n");
		close(tcpsock);
		return -1;
	}
	duration = ntohl(ackpkt.duration);

	gettimeofday(&startts, NULL);
	gap = (1400+UDPIPHEADERSZ)*0.008/capacity;//s
	gapts.tv_sec = floor(gap);
	gapts.tv_usec = (gap - gapts.tv_sec)*1e6;
	probepkt.id = MEAS;
	while(1)
	{
		seq1 = htonl(++seq);
		gettimeofday(&sendts, NULL);
		probepkt.seq = seq1;
		probepkt.secs = htonl(sendts.tv_sec);
		probepkt.usecs = htonl(sendts.tv_usec);
		memcpy(buf, (char *)&probepkt, sizeof(struct _probe));

		ret = sendto(udpsock, buf, 1400, 0, 
				(struct sockaddr *)from, fromlen);
		if(ret == -1)
		{
			perror("cannot send\n");
			close(udpsock);
			return -1;
		}

		gettimeofday(&endts, NULL);
		diffts = prober_packet_gap(startts, endts);
		gapts2 = prober_packet_gap(diffts, gapts);

		//if(gap > sleepRes)
		prober_swait(gapts2, sleepRes);
		//else
		//	prober_sbusywait(gapts2);

		gettimeofday(&startts, NULL);

		FD_ZERO(&readset);
		FD_SET(tcpsock, &readset);
		tout.tv_sec = 0; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			return -1;
		}
		else if(ret == 0) //timeout
		{
		}
		else
		{
			if(FD_ISSET(tcpsock, &readset))
			{
				ret = readwrapper(tcpsock, (char *)&endpkt, 
						sizeof(struct _mflowend));
				if(ret == -1 || endpkt.header.ptype != P_MEASFLOW_END)
				{
					fprintf(stderr, "SERV: error reading or wrong packet type.\n");
					close(tcpsock);
					return -1;
				}
				*recvrate = ntohl(endpkt.recvrate);
				break;
			}
		}
	}

	return 0;
}

int mflowReceiver(int tcpsock, int udpsock, double *recvrate, FILE *fp)
{
	pmflowstart startpkt;
	pmflowstartack ackpkt;
	pmflowend endpkt;
	pprobe *probepkt;
	int ret = 0, nrecvd = 0;
	struct timeval startts, endts, diffts, oldts, tsbucket;
	struct timeval tout;
	fd_set readset;
	int maxfd = udpsock + 1;
	struct sockaddr_in from;
	char buf[2000];
	unsigned long seq = 0;

	double sendtstamp = 0;

	//fprintf(fp, "### MEAS ###\n");

	ret = readwrapper(tcpsock, (char *)&startpkt,
			sizeof(struct _mflowstart));
	if(ret == -1)
	{
		fprintf(stderr, "error reading: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(startpkt.header.ptype != P_MEASFLOW_START)
	{
		fprintf(stderr, "Bad capstart message!\n");
		close(tcpsock);
		return -1;
	}

	ackpkt.header.ptype = P_MEASFLOW_START_ACK;
	ackpkt.header.length = 0;
	ackpkt.duration = htonl(MFLOWDURATION); //s
	ret = writewrapper(tcpsock, (char *)&ackpkt, sizeof(struct _mflowstartack));
	if(ret == -1)
	{
		fprintf(stderr, "error writing: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	gettimeofday(&startts, NULL);
	tsbucket = oldts = startts;
	probepkt = (struct _probe *)buf;

	while(1)
	{
		FD_ZERO(&readset);
		FD_SET(udpsock, &readset);
		tout.tv_sec = 60; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			close(udpsock);
			return -1;
		}
		else if(ret == 0) //timeout
		{
		}
		if(FD_ISSET(udpsock, &readset))
		{
			unsigned int fromlen = sizeof(struct sockaddr_in);
			struct timeval ts;
			ret = recvfrom(udpsock, buf, 2000, 0, 
					(struct sockaddr *)&from, &fromlen);
			if(ret == -1)
			{
				fprintf(stderr, "recv error on UDP\n");
				return -1;
			}
			if(probepkt->id != MEAS) continue;
#ifndef OSX
			if (ioctl(udpsock, SIOCGSTAMP, &ts) < 0)
			{
				gettimeofday(&ts,NULL);
			}
#else
			gettimeofday(&ts,NULL);
#endif

			seq = ntohl(probepkt->seq);
			sendtstamp = ntohl(probepkt->secs) + ntohl(probepkt->usecs)*1e-6;

			//fprintf(fp, "%f %f %ld %d\n", sendtstamp, ts.tv_sec + ts.tv_usec*1e-6, seq, MEAS);
		}

		nrecvd++;
		gettimeofday(&endts, NULL);
		diffts = prober_packet_gap(startts, endts);
		if(diffts.tv_sec + diffts.tv_usec*1.0e-6 > MFLOWDURATION)
		break;
	}

	*recvrate = nrecvd*(1400+UDPIPHEADERSZ)*0.008 
			/(diffts.tv_sec + diffts.tv_usec*1.0e-6);

	endpkt.header.ptype = P_MEASFLOW_END;
	endpkt.header.length = 0;
	endpkt.recvrate = htonl(*recvrate);
	ret = writewrapper(tcpsock, (char *)&endpkt,
			sizeof(struct _mflowend));
	if(ret == -1)
	{
		fprintf(stderr, "error writing to server: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	return 0;
}

