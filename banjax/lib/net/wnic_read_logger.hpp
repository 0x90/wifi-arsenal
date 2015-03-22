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

#ifndef NET_WNIC_READ_LOGGER_HPP
#define NET_WNIC_READ_LOGGER_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

	/**
    * wnic_read_logger is a wnic_wrapper class that logs all reads
    * to a capture file.
    */
   class wnic_read_logger : public wnic_wrapper {
   public:

      /**
       * wnic_read_logger constructor.
       *
       * \param wnic A wnic_sptr to the wrapped wnic.
       */
      explicit wnic_read_logger(wnic_sptr wnic);

      /**
       * wnic_read_logger virtual destructor.
       */
      virtual ~wnic_read_logger();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   private:

      /**
       * libpcap handle for pcap_open_dead.
       */
      pcap_t *dead_;

      /**
       * libpcap handle to the file being written to.
       */
      pcap_dumper_t *dump_;

      /**
       * Pointer to the datalink used to parse/format frame headers
       * and manage the filter-offset logic.
       */
      datalink_sptr dl_;

   };

}

#endif // NET_WNIC_READ_LOGGER_HPP
