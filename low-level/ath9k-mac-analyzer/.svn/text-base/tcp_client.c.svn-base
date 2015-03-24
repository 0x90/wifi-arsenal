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
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "packet.h"
#include "tcpclient.h"
#include "diffprobe.h"


int connect_nonb(int sockfd, const struct sockaddr *saptr, socklen_t salen, int nsec)
{
	int flags, n, error;
	socklen_t len;
	fd_set rset, wset;
	struct timeval tval;

	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ( (n = connect(sockfd, (struct sockaddr *) saptr, salen)) < 0)
		if (errno != EINPROGRESS)
		return(-1);

	/* Do whatever we want while the connect is taking place. */
	if (n == 0)
	goto done;	/* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = nsec;
	tval.tv_usec = 0;

	if((n = select(sockfd+1, &rset, &wset, NULL, nsec ? &tval : NULL)) == 0)
	{
		close(sockfd);		/* timeout */
		errno = ETIMEDOUT;
		return(-1);
	}

	if(FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset))
	{
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
		return(-1);			/* Solaris pending error */
	}
	else
	{
		fprintf(stderr, "select error: sockfd not set");
		return(-1);
	}

done:
	fcntl(sockfd, F_SETFL, flags);	/* restore file status flags */
	if (error)
	{
		close(sockfd);		/* just in case */
		errno = error;
		return(-1);
	}

	return(0);
}

int connect2server(unsigned int serverip, int fileid)
{
	int       conn_s;
	struct    sockaddr_in servaddr;
	//short int port = SERV_PORT;
	extern short int serv_port;
	short int port = serv_port;
	int ret = 0;
	int sndsize = 1024*1024;
	extern double TB_RATE_AVG_INTERVAL;

	if ( (conn_s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) 
	{
		fprintf(stderr, "CLNT: Error creating listening socket.\n");
		return -1;
	}

	ret = setsockopt(conn_s, SOL_SOCKET, SO_SNDBUF, 
			(char *)&sndsize, sizeof(int));
	sndsize = 1024*1024;
	ret = setsockopt(conn_s, SOL_SOCKET, SO_RCVBUF, 
			(char *)&sndsize, sizeof(int));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(port);
	servaddr.sin_addr.s_addr = serverip;

	if (connect_nonb(conn_s, (struct sockaddr *)&servaddr, sizeof(servaddr), 5) < 0 )
	{
		//printf("Cannot connect to server. Server may be busy; please try in a few minutes.\n");
		return -1;
	}

	pnewclientpacket pkt;
	pkt.header.ptype = P_NEWCLIENT;
	pkt.header.length = 0;
	pkt.version = htonl(VERSION);
	pkt.fileid = 0;
	pkt.delta = TB_RATE_AVG_INTERVAL;
	writewrapper(conn_s, (char *)&pkt, sizeof(struct _newclientpkt));

	pnewclientack pnewack;
	readwrapper(conn_s, (char *)&pnewack, sizeof(struct _newclientack));
	if(pnewack.header.ptype != P_NEWCLIENT_ACK)
	{
		printf("Error: bad packet type: %d\n", pnewack.header.ptype);
		close(conn_s);
		return -1;
	}
	if(pnewack.compatibilityFlag == 0)
	{
		printf("Incompatible server. Please download the latest version of ShaperProbe client from:\nhttp://www.cc.gatech.edu/~partha/diffprobe/shaperprobe.html\n");
		return -1;
	}

	return conn_s;
}

int udpclient(unsigned int serverip, unsigned int targetport)
{
	int conn_s;
	struct    sockaddr_in servaddr;
	int sndsize = 1024*1024, ret = 0;

	if ((conn_s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		fprintf(stderr, "Error creating socket.\n");
		return -1;
	}

	ret = setsockopt(conn_s, SOL_SOCKET, SO_SNDBUF, 
			(char *)&sndsize, sizeof(int));
	sndsize = 1024*1024;
	ret = setsockopt(conn_s, SOL_SOCKET, SO_RCVBUF, 
			(char *)&sndsize, sizeof(int));

	return conn_s;

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(targetport);
	servaddr.sin_addr.s_addr = serverip;

	if (connect(conn_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
	{
		printf("Error calling connect()\n");
		return -1;
	}

	return conn_s;
}

#ifdef _PAIRS_
double estimateCapacity_pairs(int tcpsock, int udpsock)
{
	pcapeststart pcap;
	pcapestack pcapack;
	int udpsock = 0;
	char buf[2000];
	int ret;
	struct timeval tv;
	double ct = 0;

	pcap.header.ptype = P_CAPEST_START;
	pcap.header.length = 0;
	writewrapper(tcpsock, (char *)&pcap, sizeof(struct _capeststart));
	ret = readwrapper(tcpsock, (char *)&pcapack, sizeof(struct _capestack));
	if(ret == -1 || pcapack.header.ptype != P_CAP_ACK)
	{
		fprintf(stderr, "cannot read OR wrong cap ack\n");
		return -1;
	}

	udpsock = udpclient();
	while(1)
	{
		gettimeofday(&tv, NULL);
		ct = tv.tv_sec + tv.tv_usec/1.0e6;
		memcpy(buf, (const char *)&ct, sizeof(ct));
		ret = send(udpsock, buf, 500, 0);
		if(ret == -1)
		{
			fprintf(stderr, "cannot send\n");
			return -1;
		}
		ret = send(udpsock, buf, 500, 0);
		if(ret == -1)
		{
			fprintf(stderr, "cannot send\n");
			return -1;
		}

		ret = readwrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1 || pcapack.header.ptype != P_CAP_ACK)
		{
			fprintf(stderr, "cannot read OR wrong cap ack\n");
			return -1;
		}
		//printf("Capacity: %.2f\n", pcapack.capacity);
		printf("."); fflush(stdout);
		if(ntohl(pcapack.finalflag) == 1) break;
		usleep(30000);
	}

	close(udpsock);

	printf("Capacity: %d\n", ntohl(pcapack.capacity));
	return pcapack.capacity;
}
#else
double estimateCapacity(int tcpsock, int udpsock, struct sockaddr_in *from)
{
	pcapeststart pcap;
	pcapestack pcapack;
	ptrainprobe probepkt;
	char buf[2000];
	int ret, count = 0, niters = 0;
	int trainlength = 5;
	struct sockaddr_in frm = *from;
	int fromlen = sizeof(struct sockaddr_in);
	unsigned char seq = 0;
	struct timeval ts;

	pcap.header.ptype = P_CAPEST_START;
	pcap.header.length = 0;
	writewrapper(tcpsock, (char *)&pcap, sizeof(struct _capeststart));
	ret = readwrapper(tcpsock, (char *)&pcapack, sizeof(struct _capestack));
	if(ret == -1 || pcapack.header.ptype != P_CAP_ACK)
	{
		fprintf(stderr, "cannot read OR wrong cap ack\n");
		return -1;
	}
	trainlength = ntohl(pcapack.trainlength);

	//udpsock = udpclient();
	while(1)
	{
		probepkt.id = niters + 10; //trains start with id 10
		for(count = 0; count < trainlength; count++)
		{
			seq = count;
			gettimeofday(&ts, NULL);
			probepkt.seq = seq;
			probepkt.secs = htonl(ts.tv_sec);
			probepkt.usecs = htonl(ts.tv_usec);
			memcpy(buf, (char *)&probepkt, sizeof(struct _trainprobe));

			ret = sendto(udpsock, buf, 1400, 0, 
					(struct sockaddr *)&frm, fromlen);
			if(ret == -1)
			{
				perror("cannot send\n");
				return -1;
			}
		}
		niters++;

		ret = readwrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1 || pcapack.header.ptype != P_CAP_ACK)
		{
			fprintf(stderr, "cannot read OR wrong cap ack\n");
			return -1;
		}
		trainlength = ntohl(pcapack.trainlength);
		printf("\33[2K\r"); printf("Upload packet train %d: %d Kbps", niters, ntohl(pcapack.capacity)); fflush(stdout);
		if(ntohl(pcapack.finalflag) == 1) break;
		usleep(500000);
	}

	printf("\33[2K\r"); fflush(stdout);
	return ntohl(pcapack.capacity);
}
#endif

int sendCapEst(int tcpsock)
{
	pcapeststart pcap;
	pcapestack pcapack;
	int ret = 0;

	ret = readwrapper(tcpsock, (char *)&pcap, sizeof(struct _capeststart));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(pcap.header.ptype != P_CAPEST_START)
	{
		fprintf(stderr, "Bad capstart message!\n");
		close(tcpsock);
		return -1;
	}

	pcapack.header.ptype = P_CAP_ACK;
	pcapack.header.length = 0;
	pcapack.capacity = pcapack.finalflag = 0;
	pcapack.trainlength = htonl(TRAIN_LENGTH);
	ret = writewrapper(tcpsock, (char *)&pcapack, 
			sizeof(struct _capestack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	return 0;
}

