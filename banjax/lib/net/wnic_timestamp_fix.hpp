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

#ifndef NET_WNIC_TIMESTAMP_FIX_HPP
#define NET_WNIC_TIMESTAMP_FIX_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_timestamp_fix is a wnic_wrapper class that ensures every
    * frame has both a TIMESTAMP1 and a TIMESTAMP2. It computes the
    * txtime for every frame it reads and uses this to compute the
    * buffer_info's TIMESTAMP1 or TIMESTAMP2 from the existing
    * timestamp value.
    */
   class wnic_timestamp_fix : public wnic_wrapper {
   public:

      /**
       * wnic_timestamp_fix constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       */
      explicit wnic_timestamp_fix(wnic_sptr wnic);

      /**
       * wnic_timestamp_fix virtual destructor.
       */
      virtual ~wnic_timestamp_fix();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. This
       * method computes the frame's txtime and then adjusts
       * TIMESTAMP1 or TIMESTAMP2 as appropriate.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   };

}

#endif // NET_WNIC_TIMESTAMP_FIX_HPP
