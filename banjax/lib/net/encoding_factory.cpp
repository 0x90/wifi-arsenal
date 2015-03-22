/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#include <net/dsss_encoding.hpp>
#include <net/dsss_ofdm_encoding.hpp>
#include <net/encoding.hpp>
#include <net/fhss_encoding.hpp>
#include <net/ofdm_encoding.hpp>
#include <util/exceptions.hpp>

#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace net;
using namespace std;
using util::raise;

encoding_sptr
encoding::get(string what)
{
   encoding_sptr enc;
   if(dsss_encoding::get()->name() == what) {
      enc = dsss_encoding::get();
   } else if(dsss_ofdm_encoding::get()->name() == what) {
      enc = dsss_ofdm_encoding::get();
   } else if(fhss_encoding::get()->name() == what) {
      enc = fhss_encoding::get();
   } else if(ofdm_encoding::get()->name() == what) {
      enc = ofdm_encoding::get();
   } else {
      ostringstream msg;
      msg << "unrecognized channel encoding (" << what << ")";
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   return enc;
}
