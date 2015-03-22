/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 */

#define __STDC_CONSTANT_MACROS
#include <net/buffer.hpp>
#include <net/offline_wnic.hpp>
#include <util/exceptions.hpp>
#include <util/syscall_error.hpp>

using namespace net;
using namespace std;
using boost::shared_ptr;
using util::raise;
using util::syscall_error;

offline_wnic::offline_wnic(string path) :
   abstract_wnic(path),
   pcap_(NULL)
{
   char err[PCAP_ERRBUF_SIZE];
   pcap_ = pcap_open_offline(path.c_str(), err);
   if(!pcap_) {
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, err);
   }
   dl_ = datalink::get(pcap_datalink(pcap_));
}

offline_wnic::~offline_wnic()
{
   pcap_close(pcap_);
}

int
offline_wnic::datalink_type() const
{
   return dl_->type();
}

void
offline_wnic::filter(string filter_expr)
{
   struct bpf_program bpf;
   if(-1 == pcap_compile(pcap_, &bpf, filter_expr.c_str(), 1, 0 /* PCAP_NETMASK_UNKNOWN */)) {
      ostringstream msg;
      msg << "pcap_compile(pcap_, &bpf, \"";
      msg << filter_expr;
      msg << "\", 1, PCAP_NETMASK_UNKNOWN): " << pcap_geterr(pcap_) << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   if(-1 == pcap_setfilter(pcap_, &bpf)) {
      ostringstream msg;
      msg << "pcap_setfilter(pcap_, &bpf): " << pcap_geterr(pcap_) << endl;
      pcap_freecode(&bpf); // NB: avoid leaking when pcap_setfilter fails
      raise<runtime_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   pcap_freecode(&bpf);
}

buffer_sptr
offline_wnic::read()
{
   buffer_sptr b;
   struct pcap_pkthdr hdr;
   const uint8_t *octets = pcap_next(pcap_, &hdr);
   if(octets) {
      b = dl_->parse(hdr.caplen, octets);
      uint64_t ts = (hdr.ts.tv_sec * UINT64_C(1000000)) + hdr.ts.tv_usec;
      buffer_info_sptr info(b->info());
      info->timestamp_wallclock(ts);
   }
   return b;
}
