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
#include <net/wnic_write_logger.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using boost::shared_ptr;
using util::raise;

wnic_write_logger::wnic_write_logger(wnic_sptr wnic) :
   wnic_wrapper(wnic),
   dl_()
{
   const int max_snapshot_len = 65535;
   const int dlt = wnic->datalink_type();
   dead_ = pcap_open_dead(dlt, max_snapshot_len);
   string file_name(wnic->name() + "-write.pcap");
   dump_ = pcap_dump_open(dead_, file_name.c_str());
   if(!dump_) {
      ostringstream msg;
      msg << wnic->name() << ": " << pcap_geterr(dead_);
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   dl_ = datalink::get(dlt);
}

wnic_write_logger::~wnic_write_logger()
{
   pcap_dump_close(dump_);
   pcap_close(dead_);
}

void
wnic_write_logger::write(const buffer& b)
{
   size_t n = 0;
   struct pcap_pkthdr hdr;
   gettimeofday(&hdr.ts, NULL);

   uint8_t buf[b.data_size() + 1024];
   const size_t buf_sz = sizeof(buf);
   hdr.len = hdr.caplen = dl_->format(b, buf_sz, buf);
   u_char *pcap = reinterpret_cast<u_char*>(dump_);
   pcap_dump(pcap, &hdr, buf);
   wnic_->write(b);
}
