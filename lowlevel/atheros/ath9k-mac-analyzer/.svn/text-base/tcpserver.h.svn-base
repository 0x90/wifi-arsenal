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

#ifndef _TCPSERVER_
#define _TCPSERVER_

#include "packet.h"

int create_server();
int preprocess_newclient(int conn_s, int udpsock0, 
		double *upcap, double *downcap, struct sockaddr_in *from, char *tracefile, FILE *fp);
int postprocess_client(int tcpsock, const char *filename, const char *sndfilename, const int probedir, char **env);
int handle_clients(int list_s, int udpsock0);

double capacityEstimation(int tcpsock, int udpsock0, 
		struct sockaddr_in *from, FILE *fp);
double wlanEstimate(struct timeval *trecv, int nrecvd, FILE *fp);

int setfilename(int fileid, char *tracefile);

#endif

