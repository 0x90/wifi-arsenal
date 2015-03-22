/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2011 Steve Glass
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

#include <net/plain_datalink.hpp>
#include <net/radiotap_datalink.hpp>
#include <util/exceptions.hpp>

#include <pcap.h>

using namespace net;
using namespace std;
using util::raise;

datalink_sptr plain(new plain_datalink);
datalink_sptr radiotap(new radiotap_datalink);

datalink_sptr
datalink::get(int datalink_type)
{
   datalink_sptr dl;
   switch(datalink_type) {
   case DLT_IEEE802_11:
      dl = plain;
      break;
   case DLT_IEEE802_11_RADIO:
      dl = radiotap;
      break;
   default:
      ostringstream msg;
      msg << "unsupported datalink type (";
      msg << "datalink_type=" << hex << datalink_type << ")";
      msg << ")" << endl;
      raise<runtime_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   return dl;
}
