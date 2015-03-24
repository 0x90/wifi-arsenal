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

#ifndef _DIFFPROBE_H_
#define _DIFFPROBE_H_

#define VERSION 3
#define RATE_FACTOR 0.9
#define RATE_DROP_FACTOR 2
#define LOSS_RATE_THRESH 0.2

#define SELECTPORT 55000
#define NUM_SELECT_SERVERS 3
#define SERV_PORT (55005)
#define SERV_PORT_UDP (55005)
#define MAX_NLIPS 1//5

#define LISTENQ (10)
#define TRAIN_LENGTH 50 
#define NITERATIONS 10
#define SUBTRAINLEN 6
#define TRAINGGTHRESH 0.5
#define TRAINEQTHRESH 0.1
#define GG(A,B) (A/B > 1+TRAINGGTHRESH)
#define EQ(A,B) (A/B > 1-TRAINEQTHRESH && A/B < 1+TRAINEQTHRESH)

#define TBDURATION 60
//#define TB_RATE_AVG_INTERVAL 0.3
#define TB_RATE_LOG_INTERVAL 0.05
#define TB_NPRIOR 3
#define TB_NPOSTERIOR 8
#define TB_NTOTLOSSPOSTERIOR 20
#define TB_RATERATIO 1.10 //1.25
#define TB_LOSSRATE 0.1
#define TB_TOTLOSSRATE 0.01
#define TB_SMOOTH_WINDOW 11
#define TB_SMOOTH_WINDOW_HALF 5
#define TB_SMOOTH_WINDOW_HALF_HALF 2
#define TB_SMOOTH_THRESH TB_RATERATIO
#define TB_MAX_TRAINLEN 5

#define MFLOWDURATION 5

#define UDPIPHEADERSZ 28


int prober_bind_port(int port);

double prober_sleep_resolution();
void prober_sbusywait(struct timeval);
void prober_swait(struct timeval, double sleepRes);
struct timeval prober_packet_gap(struct timeval y, struct timeval x);

int tbdetectReceiver(int tcpsock, int udpsock, double capacity, double sleepRes, unsigned int *result, unsigned int *minbktdepth, unsigned int *maxbktdepth, double *tbrate, unsigned int *abortflag, FILE *fp);
int tbdetectSender(int tcpsock, int udpsock, struct sockaddr_in *from, double capacity, double sleepRes, unsigned int *result, unsigned int *minbktdepth, unsigned int *maxbktdepth, double *tbrate, unsigned int *abortflag, FILE *fp);
void printShaperResult(unsigned int tbresult, unsigned int tbmindepth, unsigned int tbmaxdepth, double tbrate, unsigned int tbabortflag, int dir, FILE *fp);

int mflowSender(int tcpsock, int udpsock, struct sockaddr_in *from, double capacity, double sleepRes, double *meascap);
int mflowReceiver(int tcpsock, int udpsock, double *meascap, FILE *fp);

#define CHKRET(a) if(a != -1); \
	else return -1
#define CHKRETPTR(a) if(a != NULL); \
	else return -1

#endif

