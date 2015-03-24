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

#ifndef _PACKET_H
#define _PACKET_H

enum ptypes
{
	P_NEWCLIENT,
	P_NEWCLIENT_ACK,
	P_CAPEST_START,
	P_CAP_ACK,
	P_TBDETECT_START,
	P_TBDETECT_START_ACK,
	P_TBDETECT_END,
	P_RECVDATA,
	P_MEASFLOW_START,
	P_MEASFLOW_START_ACK,
	P_MEASFLOW_END
};

enum probetypes
{
	CAP,
	MEAS,
	TB,
	BLP_P,
	LIP_P,
	LDP_P,
	BLP_A,
	LIP_A,
	LDP_A,
	BLP_AP,
	LIP_AP,
	LDP_AP
};

enum flow { flowP, flowA };

typedef struct _header
{
	unsigned char ptype;
	unsigned int length;
} __attribute__((packed)) pheader;

typedef struct _newclientpkt
{
	pheader header;
	unsigned int version;
	unsigned int fileid;
	double delta;
} __attribute__((packed)) pnewclientpacket;

typedef struct _newclientack
{
	pheader header;
	unsigned char compatibilityFlag;
} __attribute__((packed)) pnewclientack;

typedef struct _capeststart
{
	pheader header;
} __attribute__((packed)) pcapeststart;

typedef struct _capestack
{
	pheader header;
	unsigned int capacity;//Kbps
	unsigned int finalflag;
	unsigned int trainlength;
} __attribute__((packed)) pcapestack;

typedef struct _tbdetectstart
{
	pheader header;
} __attribute__((packed)) ptbdetectstart;

typedef struct _tbdetectstartack
{
	pheader header;
	unsigned int duration;
} __attribute__((packed)) ptbdetectstartack;

typedef struct _tbdetectend
{
	pheader header;
	unsigned int result;
	unsigned int minbucketDepth;
	unsigned int maxbucketDepth;
	unsigned int tokenRate; //Kbps
	unsigned int abortflag;
} __attribute__((packed)) ptbdetectend;

typedef struct _rcvdata
{
	pheader header;
	unsigned int datalength;
} __attribute__((packed)) prcvdata;

typedef struct _mflowstart
{
	pheader header;
} __attribute__((packed)) pmflowstart;

typedef struct _mflowstartack
{
	pheader header;
	unsigned int duration;
} __attribute__((packed)) pmflowstartack;

typedef struct _mflowend
{
	pheader header;
	unsigned int recvrate;
} __attribute__((packed)) pmflowend;

typedef struct _probe
{
	unsigned int seq;
	unsigned int secs;
	unsigned int usecs;
	unsigned char id;
} __attribute__((packed)) pprobe;

typedef struct _trainprobe
{
	unsigned char seq;
	unsigned int secs;
	unsigned int usecs;
	unsigned char id;
} __attribute__((packed)) ptrainprobe;


int readwrapper(int sock, char *buf, size_t size);
int writewrapper(int sock, char *buf, size_t size);

#endif

