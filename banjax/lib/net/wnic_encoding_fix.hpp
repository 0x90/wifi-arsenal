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

#ifndef NET_WNIC_ENCODING_FIX_HPP
#define NET_WNIC_ENCODING_FIX_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_encoding_fix is a wnic_wrapper class that ensures every
    * frame has its encoding properly set. For any frame which has no
    * encoding the default will be applied.
    */
   class wnic_encoding_fix : public wnic_wrapper {
   public:

      /**
       * wnic_encoding_fix constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       * \param flags A channel_flags_t specifying the default channel flags.
       */
      explicit wnic_encoding_fix(wnic_sptr wnic, flags_t channel_flags);

      /**
       * wnic_encoding_fix virtual destructor.
       */
      virtual ~wnic_encoding_fix();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. This
       * method ensures that every frame read will have an encoding.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   private:

      /**
       * The default flags to apply if none is present on a buffer.
       */
      flags_t default_channel_flags_;

   };

}

#endif // NET_WNIC_ENCODING_FIX_HPP
