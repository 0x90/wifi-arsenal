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

#ifndef NET_WNIC_TIMESTAMP_SWIZZLE_HPP
#define NET_WNIC_TIMESTAMP_SWIZZLE_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_timestamp_swizzle is a wnic_wrapper class that swaps the
    * buffer_info's TIMESTAMP1/TIMESTAMP2 values. This is necessary
    * because some drivers (ath5k/ath9k) provide a TIMESTAMP2 but
    * claim it to be the TIMESTAMP1 value.
    */
   class wnic_timestamp_swizzle : public wnic_wrapper {
   public:

      /**
       * wnic_timestamp_swizzle constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       */
      explicit wnic_timestamp_swizzle(wnic_sptr wnic);

      /**
       * wnic_timestamp_swizzle virtual destructor.
       */
      virtual ~wnic_timestamp_swizzle();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. This
       * method swaps TIMESTAMP1 and TIMESTAMP2 in the buffer_info for
       * every object it reads.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   };

}

#endif // NET_WNIC_TIMESTAMP_SWIZZLE_HPP
