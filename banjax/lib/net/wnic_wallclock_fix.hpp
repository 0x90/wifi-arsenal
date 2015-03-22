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

#ifndef NET_WNIC_WALLCLOCK_FIX_HPP
#define NET_WNIC_WALLCLOCK_FIX_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_wallclock_fix is a wnic_wrapper class that ensures every
    * frame has a TIMESTAMP_WALLCLOCK. If the frame has such a
    * timestamp then its left untouched (e.g. reading from a libpcap
    * file will use the timestamp recorded there); otherwise one is
    * obtained when the frame is read.
    */
   class wnic_wallclock_fix : public wnic_wrapper {
   public:

      /**
       * wnic_wallclock_fix constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       */
      explicit wnic_wallclock_fix(wnic_sptr wnic);

      /**
       * wnic_wallclock_fix virtual destructor.
       */
      virtual ~wnic_wallclock_fix();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. This
       * method computes the frame's txtime and makes sure that the
       * TIMESTAMP_WALLCLOCK is set for all frames.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   };

}

#endif // NET_WNIC_WALLCLOCK_FIX_HPP
