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

#ifndef NET_WNIC_WRITE_LOGGER_HPP
#define NET_WNIC_WRITE_LOGGER_HPP

#include <net/wnic_wrapper.hpp>

#include <pcap.h>

namespace net {

   /**
    * wnic decorator that logs all writes to a capture file.
    */
   class wnic_write_logger : public wnic_wrapper {
   public:

      /**
       * Constructor for the wnic_write_logger.
       *
       * \param wnic A wnic_sptr to the wnic object to wrap.
       */
      explicit wnic_write_logger(wnic_sptr wnic);

      /**
       * Virtual destructor for the wnic_write_logger class.
       */
      virtual ~wnic_write_logger();

      /**
       * Writes a buffer to a wnic.
       *
       * \param buf A reference to the buffer to write.
       */
      virtual void write(const buffer& buf);

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

#endif // NET_WNIC_WRITE_LOGGER_HPP
