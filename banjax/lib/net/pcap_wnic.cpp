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

#include <net/buffer.hpp>
#include <net/pcap_wnic.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using boost::shared_ptr;
using util::raise;

pcap_wnic::pcap_wnic(string dev_name) :
   abstract_wnic(dev_name),
   pcap_(NULL),
   dl_()
{
   char errbuf[PCAP_ERRBUF_SIZE];
   const int max_snapshot_len = 65535;
   pcap_ = pcap_open_live(dev_name.c_str(), max_snapshot_len, 1, 0, errbuf);
   if(!pcap_) {
      ostringstream msg;
      msg << dev_name << ": " << errbuf;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   dl_ = datalink::get(pcap_datalink(pcap_));
}

pcap_wnic::~pcap_wnic()
{
   if(pcap_) {
      pcap_close(pcap_);
   }
}

int
pcap_wnic::datalink_type() const
{
   return dl_->type();
}

void
pcap_wnic::filter(string filter_expr)
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
pcap_wnic::read()
{
   buffer_sptr b;
   struct pcap_pkthdr hdr;
   const uint8_t *octets = pcap_next(pcap_, &hdr);
   if(octets) {
      b = dl_->parse(hdr.caplen, octets);
      uint64_t ts = (hdr.ts.tv_sec * 1000000) + hdr.ts.tv_usec;
      buffer_info_sptr info(b->info());
      info->timestamp_wallclock(ts);
   }
   return b;
}

void
pcap_wnic::write(const buffer& b)
{
   pcap_inject(pcap_, b.data(), b.data_size());
}
