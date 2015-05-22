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

#ifndef NET_WNIC_REQUIRE_TIMESTAMPS_HPP
#define NET_WNIC_REQUIRE_TIMESTAMPS_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_require_timestamps is a wnic_wrapper class that ensures
    * that both TIMESTAMP1/TIMESTAMP2 are present and valid and
    * silently filters out those which aren't. This is necessary
    * because at high rates the measured timestamps sometimes are
    * sometimes zero valued.
    */
   class wnic_require_timestamps : public wnic_wrapper {
   public:

      /**
       * wnic_require_timestamps constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       */
      explicit wnic_require_timestamps(wnic_sptr wnic);

      /**
       * wnic_require_timestamps virtual destructor.
       */
      virtual ~wnic_require_timestamps();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. This
       * method ensures that TIMESTAMP1 and TIMESTAMP2 are present and
       * non-zero for every object it returns.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   };

}

#endif // NET_WNIC_REQUIRE_TIMESTAMPS_HPP
