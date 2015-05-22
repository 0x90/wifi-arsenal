/* copied from olsr olsr_protocol.h */

/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas T�nnesen(andreto@olsr.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * * Redistributions of source code must retain the above copyright 
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright 
 *   notice, this list of conditions and the following disclaimer in 
 *   the documentation and/or other materials provided with the 
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its 
 *   contributors may be used to endorse or promote products derived 
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 * $Id: olsr_protocol.h,v 1.23 2007/11/08 22:47:41 bernd67 Exp $
 */

#ifndef _OLSR_HEADER_H_
#define _OLSR_HEADER_H_

#include <sys/types.h>
#include <netinet/in.h>

typedef u_int8_t olsr_u8_t;
typedef u_int16_t olsr_u16_t;
typedef u_int32_t olsr_u32_t;

/* from olsr olsr_protocol.h */

/***********************************************
 *           OLSR packet definitions           *
 ***********************************************/

/*
 *Hello info
 */
struct hellinfo 
{
  olsr_u8_t   link_code;
  olsr_u8_t   reserved;
  olsr_u16_t  size;
  olsr_u32_t  neigh_addr[1]; /* neighbor IP address(es) */
} __attribute__ ((packed));

struct hellomsg 
{
  olsr_u16_t      reserved;
  olsr_u8_t       htime;
  olsr_u8_t       willingness;
  struct hellinfo hell_info[1];
} __attribute__ ((packed));

/*
 * Topology Control packet
 */

struct neigh_info
{
  olsr_u32_t       addr;
} __attribute__ ((packed));


struct tcmsg 
{
  olsr_u16_t        ansn;
  olsr_u16_t        reserved;
  struct neigh_info neigh[1];
} __attribute__ ((packed));

/*
 *Multiple Interface Declaration message
 */

/* 
 * Defined as s struct for further expansion 
 * For example: do we want to tell what type of interface
 * is associated whit each address?
 */
struct midaddr
{
  olsr_u32_t addr;
} __attribute__ ((packed));

struct midmsg 
{
  struct midaddr mid_addr[1];
} __attribute__ ((packed));

/*
 * Host and Network Association message
 */
struct hnapair
{
  olsr_u32_t   addr;
  olsr_u32_t   netmask;
} __attribute__ ((packed));

struct hnamsg
{
  struct hnapair hna_net[1];
} __attribute__ ((packed));

/*
 * OLSR message (several can exist in one OLSR packet)
 */

struct olsrmsg
{
  olsr_u8_t     olsr_msgtype;
  olsr_u8_t     olsr_vtime;
  olsr_u16_t    olsr_msgsize;
  olsr_u32_t    originator;
  olsr_u8_t     ttl;
  olsr_u8_t     hopcnt;
  olsr_u16_t    seqno;

  union 
  {
    struct hellomsg hello;
    struct tcmsg    tc;
    struct hnamsg   hna;
    struct midmsg   mid;
  } message;

} __attribute__ ((packed));

/*
 * Generic OLSR packet
 */

struct olsr 
{
  olsr_u16_t	  olsr_packlen;		/* packet length */
  olsr_u16_t	  olsr_seqno;
  struct olsrmsg  olsr_msg[1];          /* variable messages */
} __attribute__ ((packed));

/*
 *Message Types
 */

#define HELLO_MESSAGE         1
#define TC_MESSAGE            2
#define MID_MESSAGE           3
#define HNA_MESSAGE           4

#define LQ_HELLO_MESSAGE      201
#define LQ_TC_MESSAGE         202

/*
 *Link Types
 */

#define UNSPEC_LINK           0
#define ASYM_LINK             1
#define SYM_LINK              2
#define LOST_LINK             3
#define HIDE_LINK             4
#define MAX_LINK              4

/*
 *Neighbor Types
 */

#define NOT_NEIGH             0
#define SYM_NEIGH             1
#define MPR_NEIGH             2
#define MAX_NEIGH             2

/*
 *Neighbor status
 */

#define NOT_SYM               0
#define SYM                   1

// serialized IPv4 OLSR header

struct olsr_header_v4
{
  olsr_u8_t  type;
  olsr_u8_t  vtime;
  olsr_u16_t size;
  olsr_u32_t orig;
  olsr_u8_t  ttl;
  olsr_u8_t  hops;
  olsr_u16_t seqno;
};

// serialized LQ_HELLO

struct lq_hello_info_header
{
  olsr_u8_t  link_code;
  olsr_u8_t  reserved;
  olsr_u16_t size;
};

struct lq_hello_header
{
  olsr_u16_t reserved;
  olsr_u8_t  htime;
  olsr_u8_t  will;
};

// serialized LQ_TC

struct lq_tc_header
{
  olsr_u16_t ansn;
  olsr_u16_t reserved;
};

#endif
