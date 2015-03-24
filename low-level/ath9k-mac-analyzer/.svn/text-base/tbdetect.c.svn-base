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

double TB_RATE_AVG_INTERVAL = 0.5;

inline struct timeval prober_packet_gap(struct timeval y, struct timeval x) //x>y
{
  struct timeval result;

  /* Perform the carry for the later subtraction by updating y. */
  if (x.tv_usec < y.tv_usec) 
  {
	  int nsec = (y.tv_usec - x.tv_usec) / 1000000.0 + 1;
	  y.tv_usec -= 1000000.0 * nsec;
	  y.tv_sec += nsec;
  }
  if (x.tv_usec - y.tv_usec > 1000000.0)
  {
	  int nsec = (x.tv_usec - y.tv_usec) / 1000000.0;
	  y.tv_usec += 1000000.0 * nsec;
	  y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result.tv_sec = x.tv_sec - y.tv_sec;
  result.tv_usec = x.tv_usec - y.tv_usec;

  return result;
}

inline void prober_swait(struct timeval tv, double sleepRes)
{
  /* Wait for based on select(2). Wait time is given in microsecs.  */
#if DEBUG
  fprintf(stderr, "Waiting for %d microseconds.\n", wait_time);
#endif
  double gap = tv.tv_sec + tv.tv_usec*1e-6, residualgap = 0;
  int nsleep = (int)floor(gap/sleepRes);
  double rgap = sleepRes*nsleep; // round off to lower sleepRes
  struct timeval tv2, tbefore, tafter, ts;

  // shouldn't happen if we're doing short trains
  if(gap < sleepRes)
  {
	  prober_sbusywait(tv);
	  return;
  }

  //round-off tv to the lower sleepRes
  tv2.tv_sec = (unsigned long)floor(rgap);
  tv2.tv_usec = (unsigned long)(1e6*(rgap - tv2.tv_sec));
  gettimeofday(&tbefore, NULL);
  select(0,NULL,NULL,NULL,&tv2);
  gettimeofday(&tafter, NULL);
  ts = prober_packet_gap(tbefore, tafter);
  rgap = ts.tv_sec+ts.tv_usec*1e-6;

  //and busy-wait for the rest
  residualgap = gap - rgap;
  if(residualgap < 0) return;
  tv2.tv_sec = (unsigned long)floor(residualgap);
  tv2.tv_usec = (unsigned long)(1e6*(residualgap - tv2.tv_sec));
  prober_sbusywait(tv2);
}

inline void prober_sbusywait(struct timeval tv)
{
	struct timeval oldtv, newtv, difftv;
	double diff = 0;
	double maxdiff = tv.tv_sec + tv.tv_usec*1.0e-6;

	gettimeofday(&oldtv, NULL);
	while(1)
	{
		gettimeofday(&newtv, NULL);
		difftv = prober_packet_gap(oldtv, newtv);
		diff += difftv.tv_sec + difftv.tv_usec*1.0e-6;
		if(diff >= maxdiff) return;
		oldtv = newtv;
	}
}

double prober_sleep_resolution()
{
	int i=0;
	struct timeval ts1, ts2, ts;
	double resarr[11] = {1};

	for(i=0; i < 11; i++)
	{
		ts.tv_sec = 0; ts.tv_usec = 10;
		gettimeofday(&ts1, NULL);
		select(0,NULL,NULL,NULL,&ts); //prober_swait(ts)
		gettimeofday(&ts2, NULL);
		ts = prober_packet_gap(ts1, ts2);
		resarr[i] = ts.tv_sec + ts.tv_usec*1.0e-6;
		usleep(10000);
	}

	int compd(const void *a, const void *b);
	qsort((void *)resarr, 11, sizeof(double), compd);

	return resarr[5];
}


int tbdetectSender(int tcpsock, int udpsock, struct sockaddr_in *from, 
		double capacity, double sleepRes, unsigned int *result,
		unsigned int *minbktdepth, unsigned int *maxbktdepth,
		double *tbrate, unsigned int *abortflag, FILE *fp)
{
	ptbdetectstart startpkt;
	ptbdetectstartack ackpkt;
	ptbdetectend endpkt;
	pprobe probepkt;
	struct timeval gapts, startts, endts, diffts, sendts, expts;
	char buf[2000];
	int ret = 0;
	int duration = 0;
	double gap = 0, start0 = 0;
	fd_set readset;
	struct timeval tout;
	int maxfd = tcpsock + 1;
	unsigned int fromlen = sizeof(struct sockaddr_in);
	unsigned long seq = 0, seq1 = 0;
	int trainlength = 1, mintrainlen = 1, maxtrainlen = TB_MAX_TRAINLEN, 
	    trainid = 0, c = 0;
	double bwperiod = 0xFFFFFFFF;

	startpkt.header.ptype = P_TBDETECT_START;
	startpkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&startpkt,
			sizeof(struct _tbdetectstart));
	if(ret == -1)
	{
		fprintf(stderr, "error writing to server: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _tbdetectstartack));
	if(ret == -1)
	{
		fprintf(stderr, "error reading from client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_TBDETECT_START_ACK)
	{
		fprintf(stderr, "Bad start message!\n");
		close(tcpsock);
		return -1;
	}
	duration = ntohl(ackpkt.duration);

	gap = (1400+UDPIPHEADERSZ)*0.008/capacity;//s
	trainlength = 1;
	mintrainlen = ceil(sleepRes/gap);
	maxtrainlen = (gap > sleepRes) ? TB_MAX_TRAINLEN : 30; // TODO: 30 -> buffer length
	for(c = mintrainlen; c <= maxtrainlen; c++)
	{
		double k = floor(c*gap/sleepRes);
		double bp = c*gap - k*sleepRes;
		if(bwperiod > bp) {bwperiod = bp; trainlength = c;}
	}
	gap *= trainlength;
	//fprintf(fp, "client trainlength: %d\n", trainlength);

	gettimeofday(&startts, NULL); start0 = startts.tv_sec+startts.tv_usec*1e-6;
	gapts.tv_sec = floor(gap);
	gapts.tv_usec = (gap - gapts.tv_sec)*1e6;
	*abortflag = 0;
	probepkt.id = TB;
	while(1)
	{
		double expsendtime = start0 + gap * trainid; // trainid starts with 1
		trainid++;

		for(c = 0; c < trainlength; c++)
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
		}

		gettimeofday(&endts, NULL);
		expts.tv_sec = floor(expsendtime);
		expts.tv_usec = 1e6*(expsendtime - floor(expsendtime));
		diffts = prober_packet_gap(endts, expts);

		if(diffts.tv_sec+diffts.tv_usec*1e-6 > 0)
		prober_swait(diffts, sleepRes);

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
						sizeof(struct _tbdetectend));
				if(ret == -1 || endpkt.header.ptype != P_TBDETECT_END)
				{
					fprintf(stderr, "SERV: error reading or wrong packet type.\n");
					close(tcpsock);
					return -1;
				}
				*result = ntohl(endpkt.result);
				*minbktdepth = ntohl(endpkt.minbucketDepth);
				*maxbktdepth = ntohl(endpkt.maxbucketDepth);
				*tbrate = ntohl(endpkt.tokenRate);
				*abortflag = ntohl(endpkt.abortflag);
				break;
			}
		}
	}

	return 0;
}

/*int tbdetectSender(int tcpsock, int udpsock, struct sockaddr_in *from, 
		double capacity, double sleepRes, unsigned int *result,
		unsigned int *minbktdepth, unsigned int *maxbktdepth,
		double *tbrate, unsigned int *abortflag, FILE *fp)
{
	ptbdetectstart startpkt;
	ptbdetectstartack ackpkt;
	ptbdetectend endpkt;
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
	unsigned long sendtstamp = 0;
	int ULSZ = sizeof(unsigned long);
	int trainlength = 1, mintrainlen = 1, maxtrainlen = TB_MAX_TRAINLEN, c = 0;
	double bwperiod = 0xFFFFFFFF;

	startpkt.header.ptype = P_TBDETECT_START;
	startpkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&startpkt,
			sizeof(struct _tbdetectstart));
	if(ret == -1)
	{
		fprintf(stderr, "error writing to server: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _tbdetectstartack));
	if(ret == -1)
	{
		fprintf(stderr, "error reading from client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_TBDETECT_START_ACK)
	{
		fprintf(stderr, "Bad start message!\n");
		close(tcpsock);
		return -1;
	}
	duration = ntohl(ackpkt.duration);

	gap = (1400+UDPIPHEADERSZ)*0.008/capacity;//s
	trainlength = 1;
	//if(gap/sleepRes < 2) trainlength = (int)ceil(2*sleepRes/gap);
	//if(trainlength > TB_MAX_TRAINLEN) trainlength = TB_MAX_TRAINLEN;
	mintrainlen = ceil(sleepRes/gap);
	maxtrainlen = (gap > sleepRes) ? TB_MAX_TRAINLEN : 30; // TODO: 30 -> buffer length
	for(c = mintrainlen; c <= maxtrainlen; c++)
	{
		double k = floor(c*gap/sleepRes);
		double bp = c*gap - k*sleepRes;
		if(bwperiod > bp) {bwperiod = bp; trainlength = c;}
	}
	fprintf(fp, "client trainlength: %d\n", trainlength);

	gettimeofday(&startts, NULL);
	gap *= trainlength;
	gapts.tv_sec = floor(gap);
	gapts.tv_usec = (gap - gapts.tv_sec)*1e6;
	*abortflag = 0;
	buf[ULSZ+ULSZ+ULSZ] = TB;
	while(1)
	{
		for(c = 0; c < trainlength; c++)
		{
			seq1 = htonl(++seq);
			gettimeofday(&sendts, NULL);
			memcpy(buf, (char *)&seq1, ULSZ);
			sendtstamp = htonl(sendts.tv_sec);
			memcpy((char *)buf+ULSZ, (char *)&sendtstamp, ULSZ);
			sendtstamp = htonl(sendts.tv_usec);
			memcpy((char *)buf+2*ULSZ, (char *)&sendtstamp, ULSZ);

			ret = sendto(udpsock, buf, 1400, 0, 
					(struct sockaddr *)from, fromlen);
			if(ret == -1)
			{
				perror("cannot send\n");
				close(udpsock);
				return -1;
			}
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
						sizeof(struct _tbdetectend));
				if(ret == -1 || endpkt.header.ptype != P_TBDETECT_END)
				{
					fprintf(stderr, "SERV: error reading or wrong packet type.\n");
					close(tcpsock);
					return -1;
				}
				*result = ntohl(endpkt.result);
				*minbktdepth = ntohl(endpkt.minbucketDepth);
				*maxbktdepth = ntohl(endpkt.maxbucketDepth);
				*tbrate = ntohl(endpkt.tokenRate);
				*abortflag = ntohl(endpkt.abortflag);
				break;
			}
		}
	}

	return 0;
}*/

inline double findmediandouble(double *arr, int n)
{
	double *tarr = (double *)malloc(n*sizeof(double));
	double median = 0;
	int compd(const void *a, const void *b);

	memcpy(tarr, arr, n*sizeof(double));
	qsort((void *)tarr, n, sizeof(double), compd);

	median = (n%2 == 1) ? tarr[(int)floor(n/2)] : (tarr[n/2-1]+tarr[n/2])/2.0;
	free(tarr);

	return median;
}

#define GT_(x,y) (1.0*x/y > TB_SMOOTH_THRESH)
inline double median_(double *arr, int lindex, int rindex)
{
	double arr2[TB_SMOOTH_WINDOW_HALF];
	int compd(const void *a, const void *b);

	memcpy((void *)arr2, (const void *)((double *)arr+lindex), 
				(rindex-lindex+1)*sizeof(double));
	qsort(arr2, rindex-lindex+1, sizeof(double), compd);

	return arr2[TB_SMOOTH_WINDOW_HALF_HALF];
}

inline int smoothFilterRate(double *rate, int *rank, int index)
{
	double medl = 0, medr = 0, val = rate[index-TB_SMOOTH_WINDOW_HALF];
	int count = 0;

	if(index+1 < TB_SMOOTH_WINDOW)
	return 0;

	medl = median_(rate, index-TB_SMOOTH_WINDOW+1, index-TB_SMOOTH_WINDOW_HALF-1);
	medr = median_(rate, index-TB_SMOOTH_WINDOW_HALF+1, index);
	if(( GT_(val, medl) && GT_(val, medr) ) ||
	   ( GT_(medl, val) && GT_(medr, val) ))
	{
		int newrank = 0;
		double oldrate = rate[index-TB_SMOOTH_WINDOW_HALF], newrate = 0;
		newrate = rate[index-TB_SMOOTH_WINDOW_HALF] = (medl+medr)/2.0;

		newrank = (newrate > oldrate) ? -0xFFFFFF : 0xFFFFFF;
		for(count = 0; count <= index; count++)
		{
			double r = rate[count];
			if(count == index-TB_SMOOTH_WINDOW_HALF) continue;
			if(r > newrate && r < oldrate)
			{
				newrank = (newrank > rank[count]) ? rank[count] : newrank;
				rank[count]++;
			}
			else if(r > oldrate && r < newrate)
			{
				newrank = (newrank < rank[count]) ? rank[count] : newrank;
				rank[count]--;
			}
		}
		if(newrank != -0xFFFFFF && newrank != 0xFFFFFF)
		rank[index-TB_SMOOTH_WINDOW_HALF] = newrank;
	}

	return 0;
}

inline int getLevelShift(double *timestamp, double *rate, int *rank, 
			int *index, double t, double rateEstimate,
			unsigned int *minbktdepth, unsigned int *maxbktdepth,
			double *tbrate)
{
	int count = 0, count2 = 0, maxcount = *index;
	unsigned int minrank = 0xFFFFFFFF;

	if(rateEstimate == 0.0)
	return 0;

	(*index)++;

	timestamp[*index] = t;
	rate[*index] = rateEstimate;

	for(count = 0; count <= maxcount; count++)
	{
		if(rateEstimate < rate[count])
		{
			minrank = (minrank > rank[count]) ? rank[count] : minrank;
			rank[count]++;
		}
		//added for equal values
		else if(rateEstimate == rate[count])
			minrank = rank[count];
	}
	if(minrank == 0xFFFFFFFF)
	rank[*index] = *index + 1;
	else
	rank[*index] = minrank;

	smoothFilterRate(rate, rank, *index); //TODO: right place?

	if(*index < TB_NPRIOR+TB_NPOSTERIOR+1) // not diagnosable
	return 0;

	minrank = 0xFFFFFFFF;
	int tbstart = -1, tbend = -1;
	double tbucket = 0, tbucketstart = 0, rateratio = 0;

	tbucket = 0;//rate[0]*TB_RATE_AVG_INTERVAL/8.0; //KB
	for(count = 0/*1*/; count < *index+1; count++)
	{
		int maxrank = -1;
		minrank = (minrank > rank[count]) ? rank[count] : minrank;

		tbucket += rate[count]*TB_RATE_AVG_INTERVAL/8.0; //KB

		for(count2 = count+1; count2 < *index+1; count2++)
		{
			maxrank = (maxrank < rank[count2]) ? rank[count2] : maxrank;
		}
		if(maxrank <= minrank) // stricter version below
		//if(minrank == rank[count] && maxrank <= minrank)
		{
			tbend = count + 1;

			//check of % of points before and after
			if(count < TB_NPRIOR || count > (*index)-TB_NPOSTERIOR)
				continue;

			//sanity check of values before and after
			rateratio = findmediandouble((rate), count+1) /
					findmediandouble((rate+count+1), *index-count);
			//if(rate[count-2] > rate[count+2]*1.25)
			if(rateratio > TB_RATERATIO)
			{
				if(tbstart == -1)
				{
					tbstart = count + 1;
					tbucketstart = tbucket;
				}
			}
		}
	}
	if(tbstart != -1)
	{
		tbucket = tbucketstart;
		double sentrate = 8.0*tbucket/(timestamp[tbstart] - timestamp[0]);

		//fprintf(stdout, "level-shift: start %d end %d\n", tbstart, tbend);
		*tbrate = findmediandouble((rate+tbend), *index-tbend+1);

		*minbktdepth = tbucket - (tbstart)*(*tbrate)*TB_RATE_AVG_INTERVAL/8.0
				- (sentrate - (*tbrate))*TB_RATE_AVG_INTERVAL/(2*8.0);
		*maxbktdepth = tbucket - (tbstart)*(*tbrate)*TB_RATE_AVG_INTERVAL/8.0
				+ (sentrate - (*tbrate))*TB_RATE_AVG_INTERVAL/(2*8.0);
		*minbktdepth *= 1.024;
		*maxbktdepth *= 1.024;
		//fprintf(stdout, "sentrate %f min %d max %d\n", sentrate, *minbktdepth, *maxbktdepth);

		return 1;
	}

	return 0;
}

inline int tbLogRateLoss(double sendtstamp, double timestamp, int size, 
			unsigned long seq, unsigned long maxseq, 
			unsigned long *lastseq, unsigned long *totrecvd, 
			double *lastbucket, int *bucketbytes, FILE *fp)
{
#ifdef AGGREGATE_LOG_
	double bucket = floor(timestamp/TB_RATE_LOG_INTERVAL);
	double rateEstimate = 0;
	if(bucket != *lastbucket)
	{
		rateEstimate = (*bucketbytes) * 0.008/TB_RATE_LOG_INTERVAL;

		//fprintf(fp, "%f %f %ld %ld\n", timestamp, rateEstimate, 
						*totrecvd, maxseq - *lastseq + 1);

		*bucketbytes = size;
		*totrecvd = 1;
		*lastseq = seq;
		*lastbucket = bucket;
	}
	else
	{
		(*totrecvd)++;
		*bucketbytes += size;
	}
#else
	//fprintf(fp, "%f %f %ld %d\n", sendtstamp, timestamp, seq, TB);
#endif

	return 0;
}

int tbdetectReceiver(int tcpsock, int udpsock, 
		double capacity, double sleepRes,
		unsigned int *result, unsigned int *minbktdepth, 
		unsigned int *maxbktdepth, double *tbrate, 
		unsigned int *abortflag, FILE *fp)
{
	ptbdetectstart startpkt;
	ptbdetectstartack ackpkt;
	ptbdetectend endpkt;
	pprobe *probepkt;
	int ret = 0;
	struct timeval startts, endts, diffts, oldts, tsbucket;
	struct timeval tout;
	fd_set readset;
	int maxfd = udpsock + 1;
	struct sockaddr_in from;
	double rateEstimate = capacity;
	double lastbucket = -1;
	int bucketbytes = 0;
	char buf[2000];

	int len = ceil(1.5*TBDURATION/TB_RATE_AVG_INTERVAL);
	double *timestamp = calloc(len, sizeof(double));
	double *rate = calloc(len, sizeof(double));
	float *lossrate = calloc(len, sizeof(float));
	int *rank = calloc(len, sizeof(int));
	int index = -1;
	unsigned long seq = 0, maxseq = 0, lastseq = 0, totrecvd = 0;
	unsigned long contHiLossWnds = 0, contLoLossWnds = 0;

	double loglastbucket = -1;
	int logbucketbytes = 0;
	unsigned long loglastseq = 0, logtotrecvd = 0;
	double sendtstamp = 0;

	//fprintf(fp, "### DATA ###\n");

	ret = readwrapper(tcpsock, (char *)&startpkt,
			sizeof(struct _tbdetectstart));
	if(ret == -1)
	{
		fprintf(stderr, "error reading: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}
	if(startpkt.header.ptype != P_TBDETECT_START)
	{
		fprintf(stderr, "Bad capstart message!\n");
		close(tcpsock);
		return -1;
	}

	ackpkt.header.ptype = P_TBDETECT_START_ACK;
	ackpkt.header.length = 0;
	ackpkt.duration = htonl(5); //s
	ret = writewrapper(tcpsock, (char *)&ackpkt, sizeof(struct _tbdetectstartack));
	if(ret == -1)
	{
		fprintf(stderr, "error writing: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	gettimeofday(&startts, NULL);
	tsbucket = oldts = startts;
	//lastbucket = floor((startts.tv_sec + startts.tv_usec*1e-6)
	//			/TB_RATE_AVG_INTERVAL);
	lastbucket = 0;
	*abortflag = endpkt.abortflag = endpkt.result = 0;
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
			if(probepkt->id != TB) continue;
#ifndef OSX
			if (ioctl(udpsock, SIOCGSTAMP, &ts) < 0)
			{
				gettimeofday(&ts,NULL);
			}
#else
			gettimeofday(&ts,NULL);
#endif
			if(totrecvd == 0)
			startts = ts;

			seq = ntohl(probepkt->seq);
			maxseq = (maxseq < seq) ? seq : maxseq;
			totrecvd++;
			sendtstamp = ntohl(probepkt->secs) + ntohl(probepkt->usecs)*1e-6;

			//double bucket = floor((ts.tv_sec + ts.tv_usec*1e-6)
			//		/TB_RATE_AVG_INTERVAL);
			double bucket = floor((ts.tv_sec + ts.tv_usec*1e-6 - 
					startts.tv_sec - startts.tv_usec*1e-6)
					/TB_RATE_AVG_INTERVAL);
			if(bucket == -1) bucket = 0;

			tbLogRateLoss(sendtstamp, ts.tv_sec + ts.tv_usec*1e-6, ret, seq, maxseq, 
					&loglastseq, &logtotrecvd, &loglastbucket, &logbucketbytes, fp);

			/*diffts = prober_packet_gap(oldts, ts);
			rateEstimate = (rateEstimate*TB_RATE_AVG_INTERVAL + ret*0.008)/
				(diffts.tv_sec + diffts.tv_usec*1.0e-6 + TB_RATE_AVG_INTERVAL);*/
			if(bucket != lastbucket)
			{
				float loss = 0;
				if(maxseq + 1 != lastseq)
				loss = 1 - 1.0*totrecvd / (maxseq - lastseq + 1);
				lossrate[index+1] = loss;

				if(loss > TB_LOSSRATE)
					contHiLossWnds++;
				else
					contHiLossWnds = 0;
				if(loss > TB_TOTLOSSRATE)
					contLoLossWnds++;
				else
					contLoLossWnds = 0;

				if(contHiLossWnds > TB_NPOSTERIOR+2 ||
				   contLoLossWnds > TB_NTOTLOSSPOSTERIOR)
				{
					//fprintf(fp, 
					//	"aborting due to high loss rate: Hi:%ld Lo:%ld\n", 
					//	contHiLossWnds, contLoLossWnds);
					*abortflag = 1;
					endpkt.abortflag = htonl(1);
					break;
				}

				rateEstimate = 
					bucketbytes * 0.008/TB_RATE_AVG_INTERVAL;
				*result = getLevelShift(timestamp, rate, rank, 
						&index, 
						tsbucket.tv_sec + tsbucket.tv_usec*1e-6, 
						rateEstimate, minbktdepth, 
						maxbktdepth, tbrate);

				if(*result == 1)
				break;

				bucketbytes = ret;
				totrecvd = 1;
				lastbucket = bucket;
				lastseq = seq;
				tsbucket = ts;
			}
			else
			{
				bucketbytes += ret;
			}
			oldts = ts;
		}

		gettimeofday(&endts, NULL);
		diffts = prober_packet_gap(startts, endts);
		if(diffts.tv_sec + diffts.tv_usec*1.0e-6 > TBDURATION)
		{
			//for(ret = 0; ret < index; ret++)
			//{
			//	printf("rate %f\n", rate[ret]);
			//}
			break;
		}
	}

	//for(ret = 0; ret < index; ret++)
	//{
	//	printf("rate %f loss %f\n", rate[ret], lossrate[ret]);
	//}

	endpkt.header.ptype = P_TBDETECT_END;
	endpkt.header.length = 0;
	endpkt.result = htonl(*result);
	endpkt.minbucketDepth = htonl(*minbktdepth);
	endpkt.maxbucketDepth = htonl(*maxbktdepth);
	if(*result != 1) *tbrate = findmediandouble(rate, index);
	endpkt.tokenRate = htonl(*tbrate);
	ret = writewrapper(tcpsock, (char *)&endpkt,
			sizeof(struct _tbdetectend));
	if(ret == -1)
	{
		fprintf(stderr, "error writing to server: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	free(timestamp);
	free(rate);
	free(lossrate);
	free(rank);
	return 0;
}

void printShaperResult(unsigned int tbresult, unsigned int tbmindepth,
			unsigned int tbmaxdepth, double tbrate, 
			unsigned int tbabortflag, int dir, FILE *fp)
{
	if(tbabortflag == 1)
	{
		return;
	}

	if(dir == 0)
	fprintf(fp, "Up: ");
	else
	fprintf(fp, "Down: ");


	if(tbresult == 0)
	{
		fprintf(fp, "0\n");
		//fprintf(fp, "Median received rate: %d Kbps.\n", (int)tbrate);
		return;
	}

	//if(tbmindepth == tbmaxdepth)
	//fprintf(fp, "Burst size: %d KB; ", tbmindepth);
	//else
	//fprintf(fp, "Burst size: %d-%d KB; ", tbmindepth, tbmaxdepth);

	fprintf(fp, "%d Kbps\n", (int)tbrate);
}

