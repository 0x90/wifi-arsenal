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

/*
* Packet replayer/cloner.
  * 
  * November 2008.
  *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __FAVOR_BSD /* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "tcpclient.h"
#include "tcpserver.h"
#include "packet.h"
#include "diffprobe.h"

#define PROBER_CONFIG "prober.conf"

/* Global paremeters from config.  */
unsigned int serverip = 0;
unsigned short int serv_port = 0;
unsigned int clientip = 0;

unsigned int verbose = 0;


/* Utility functions.  */

char * ip2str(unsigned int ip)
{
  struct in_addr ia;

  ia.s_addr = ip;

  return inet_ntoa(ia);
}

unsigned int str2ip(char *ip)
{
  struct in_addr ia;
  int r;
  r = inet_aton(ip, &ia);
  if (r) return ntohl(ia.s_addr);
  return 0;
}

void die(char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(0);
}

int tryRandServers(unsigned long *serverList, int num_servers, int fileid)
{
	int tcpsock = -1, num = 0, i = 0;
	char *visited = (char*)malloc(num_servers*sizeof(char));
	memset(visited, 0, num_servers);
	while(1)
	{	
		int flag = 0;
		for(i = 0; i < num_servers; i++)
		{
			if(visited[i] == 0)
			{
				flag = 1;
				break;
			}
		}
		if(flag == 0)
		{
			printf("All servers are busy; please try in a few minutes.\n");
			free(visited);
			return -1;
		}
		num = rand()%num_servers;
		if(visited[num] == 1)
			continue;
		visited[num] = 1;
		tcpsock = connect2server(serverList[num], fileid);
		if(tcpsock == -1)	
			continue;
		break;
	}
	serverip = serverList[num];
	free(visited);
	return tcpsock;
}

int selectServer(int fileid)
{
#define MAXDATASIZE 25
	char *selectorList[NUM_SELECT_SERVERS] = {"64.9.225.142","64.9.225.153","64.9.225.166"};
	int visited[NUM_SELECT_SERVERS];
	int num, ctr_code, sockfd, numbytes, num_servers, tcpsock;
	char buf[MAXDATASIZE], ctr_buff[8];
	struct sockaddr_in their_addr;
	char hostname[128];
	unsigned long *serverlist;

	srand(time(NULL));
	memset(visited, 0, NUM_SELECT_SERVERS*sizeof(int));
	memset(hostname, 0, 128);
	while(1)
	{
		int flag = 0;
		int i = 0;
		for(i = 0; i < NUM_SELECT_SERVERS; i++)
		{
			if(visited[i]==0)
			{
				flag = 1;
				break;
			}
		}
		if(!flag)
		{
			printf("All servers are busy. Please try again later.\n");
			return -1;
		}
		num = rand()%NUM_SELECT_SERVERS;
		if(visited[num] == 1)
			continue;
		visited[num] = 1;
		strcpy(hostname,selectorList[num]);
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{
			perror("socket");
			continue;
		}
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(SELECTPORT);
		their_addr.sin_addr.s_addr = htonl(str2ip(hostname));
		bzero((char *)&(their_addr.sin_zero),sizeof(their_addr.sin_zero));
		if(connect(sockfd,(struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1)
		{
			perror("connect");
			continue;
		}
		if((numbytes=recv(sockfd, ctr_buff, sizeof(unsigned int), 0)) == -1)
		{
			perror("recv");
			close(sockfd);
			return -1;
		}
		memcpy(&ctr_code, ctr_buff, sizeof(unsigned int));
		num_servers = ntohl(ctr_code);
		serverlist = malloc(num_servers*sizeof(unsigned long));
		for(i = 0; i < num_servers; i++)
		{
			memset(buf, 0, MAXDATASIZE);
			if((numbytes=recv(sockfd, ctr_buff, sizeof(unsigned int), 0)) == -1)
			{
				close(sockfd);
				return -1;
			}
			memcpy(&ctr_code, ctr_buff, sizeof(unsigned int));
			int size = ntohl(ctr_code);
			if((numbytes=recv(sockfd, buf, size, 0)) == -1)
			{
				perror("recv");
				close(sockfd);
				return -1;
			}
			serverlist[i] = htonl(str2ip(buf));
		}
		close(sockfd);
		break;
	}
	tcpsock = tryRandServers(serverlist, num_servers, fileid);
	free(serverlist);
	return tcpsock;
}

int prober_config_load(int argc, char **argv, char *tracefile, int *fileid)
{
  int c = 0;
  opterr = 0;

  serv_port = SERV_PORT_UDP;
  serverip = htonl(str2ip("143.215.131.173"));
  //serverip = htonl(str2ip("38.102.0.111"));

  while ((c = getopt (argc, argv, "s:p:vh")) != -1)
  {
  switch (c)
  {
  case 's':
	  serverip = htonl(str2ip(optarg));
	  break;
  case 'p':
	  serv_port = atoi(optarg);
	  break;
  case 'v':
	  verbose = 1;
	  break;
  case '?':
  case ':':
  case 'h':
  default:
	  fprintf(stderr, "ShaperProbe beta candidate.\n\n");
	  fprintf(stderr, "Usage: %s -s <server>\n", argv[0]);
	  return -1;
  }
  }
  //printf("serv_port: %u\n",serv_port);
  //printf("serverint: %u\n",serverip);
  //exit(1);
  return 0;
}

int sendData(int tcpsock, char *filename)
{
	prcvdata pkt;
	struct stat infobuf;
	int ret = 0, len = 0, bytesleft = 0;
	char *buf = NULL;
	FILE *fp;

	if(stat(filename, &infobuf) == -1)
	{
		perror("error: file");
		return -1;
	}
	len = infobuf.st_size;

	//printf("\nsending measurement data to server."); fflush(stdout);
	pkt.header.ptype = P_RECVDATA;
	pkt.header.length = 0;
	pkt.datalength = htonl(len);
	ret = writewrapper(tcpsock, (char *)&pkt, sizeof(struct _rcvdata));
	if(ret == -1)
	{
		fprintf(stderr, "CLI: error sending data to serv: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	buf = (char *)malloc(len*sizeof(char));
	fp = fopen(filename, "r");
	ret = fread((void *)buf, sizeof(char), len, fp);
	fclose(fp);

	bytesleft = len;
	while(bytesleft > 0)
	{
		int tosend = (bytesleft > 1400) ? 1400 : bytesleft;
		//ret = writewrapper(tcpsock, (char *)buf, len);
		ret = writewrapper(tcpsock, (char *)buf+(len-bytesleft), tosend);
		if(ret == -1)
		{
			fprintf(stderr, "CLI: error sending data to serv: %d\n", tcpsock);
			perror("");
			close(tcpsock);
			free(buf);
			return -1;
		}
		bytesleft -= ret;
	}

	//printf(".done.\n\n");
	printf("\n");
	free(buf);
	return 0;
}


int main(int argc, char *argv[])
{
  int tcpsock = 0;
  int udpsock = 0;
  struct sockaddr_in from;
  double capacityup = 0, capacitydown = 0;
  double measupcap = 0, measdowncap = 0;
  unsigned int tbresult = 0, tbmindepth = 0, tbmaxdepth = 0, tbabortflag = 0;
  double tbrate = 0, truecapup = 0, truecapdown = 0;
  double sleepRes = 1;
  char filename[256], tracefile[256];
  int fileid = -1;
  struct in_addr sin_addr;
  struct timeval tv;
  FILE *fp;
  extern double TB_RATE_AVG_INTERVAL;

  TB_RATE_AVG_INTERVAL = 0.3;

  printf("DiffProbe beta release. October 2009.\n");
  printf("Shaper Detection Module.\n\n");

  memset(tracefile, 0, 256);
  CHKRET(prober_config_load(argc, argv, tracefile, &fileid));

  sleepRes = prober_sleep_resolution();

  tcpsock = connect2server(serverip, fileid);
  //tcpsock = selectServer(fileid);
  if(tcpsock <= 0) printf("Server busy. Please try again later.\n");
  CHKRET(tcpsock);

  memset(&from, 0, sizeof(from));
  from.sin_family      = PF_INET;
  //from.sin_port        = htons(SERV_PORT_UDP);
  from.sin_port        = htons(serv_port);
  from.sin_addr.s_addr = serverip;

  gettimeofday(&tv, NULL);
  sin_addr.s_addr = serverip;
  memset(filename, 0, 256);
  sprintf(filename, "%s_%d.txt", inet_ntoa(sin_addr), (int)tv.tv_sec);
  //fp = fopen(filename, "w");
  //fprintf(fp, "sleep time resolution: %.2f ms.\n", sleepRes*1000);

  //udpsock = udpclient(serverip, SERV_PORT_UDP);
  udpsock = udpclient(serverip, serv_port);
  CHKRET(udpsock);
  sin_addr.s_addr = serverip;
  printf("Connected to server %s.\n", inet_ntoa(sin_addr));

  printf("\nEstimating capacity:\n");
  capacityup = estimateCapacity(tcpsock, udpsock, &from);
  CHKRET(capacityup);
  CHKRET(sendCapEst(tcpsock));
  capacitydown = capacityEstimation(tcpsock, udpsock, &from, fp);
  CHKRET(capacitydown);

  mflowSender(tcpsock, udpsock, &from, 
	(capacityup > 100000) ? 95000 : capacityup, sleepRes, &measupcap);
  mflowReceiver(tcpsock, udpsock, &measdowncap, fp);
  //XXX: the meas code needs trains and lower cpu
  if(capacityup < 80000) capacityup = measupcap;
  if(capacitydown < 80000) capacitydown = measdowncap;
  if(capacityup > 100000)
  {
	  printf("Upstream: greater than 100 Mbps.\n");
	  capacityup = 95000;
  }
  else
  {
	  printf("Upstream: %d Kbps.\n", (int)capacityup);
//	  capacityup *= 0.95; //reduce loss-based aborts
  }
  truecapup = capacityup;
  if(capacitydown > 100000)
  {
	  printf("Downstream: greater than 100 Mbps.\n");
	  capacitydown = 95000;
  }
  else
  {
	  printf("Downstream: %d Kbps.\n", (int)capacitydown);
//	  capacitydown *= 0.95; //reduce loss-based aborts
  }
  truecapdown = capacitydown;

  printf("\nThe measurement will last for about %.1f minutes. Please wait.\n",
	0.5*ceil(2*(
	(2 * (60)  // probing + low-rate
	+ (40560 + 3.5 * capacitydown * (60) ) * 8 / (1000*capacityup))/60)));  // to upload file 

  printf("\nChecking for traffic shapers:\n\n");
  CHKRET(tbdetectSender(tcpsock, udpsock, &from, capacityup, sleepRes, 
		  &tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag, fp));
  if(tbresult == 1) truecapup = tbrate;
//  mflowSender(tcpsock, udpsock, &from, (tbresult == 1) ? tbrate : capacityup/2.0, sleepRes);
  printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 0, stdout);

  CHKRET(tbdetectReceiver(tcpsock, udpsock, capacitydown, sleepRes,
		  &tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag, fp));
  if(tbresult == 1) truecapdown = tbrate;
//  mflowReceiver(tcpsock, udpsock, fp);
  //fclose(fp);
  //sendData(tcpsock, filename);
  printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 1, stdout);

  close(udpsock);
  close(tcpsock);

  printf("\nFor more information, visit: http://www.cc.gatech.edu/~partha/diffprobe\n");

  return(0);
}

