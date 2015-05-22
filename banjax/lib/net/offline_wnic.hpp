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

#ifndef NET_OFFLINE_WNIC_HPP
#define NET_OFFLINE_WNIC_HPP

#include <net/abstract_wnic.hpp>
#include <net/datalink.hpp>

#include <pcap.h>
#include <string>

namespace net {

   /**
    * offline_wnic is a wnic implementation that reads its input from
    * a libpcap-format capture file.
    */
   class offline_wnic : public abstract_wnic {
   public:

      /**
       * Constructor for the offline_wnic class.
       *
       * \param A string containing the path to the file.
       */
      explicit offline_wnic(std::string path);

      /**
       * Virtual destructor for the offline_wnic class.
       */
      virtual ~offline_wnic();

      /**
       * Return the ARP type for this wnic.
       *
       * \return An int encoding the ARP type.
       */
      virtual int datalink_type() const;

      /**
       * Install the capture filter given by filter_expr. See
       * pcap-filter(7) for details of the filter_expr syntax.
       *
       * \param filter_expr The filter expression.
       * \throws invalid_argument If expr is not valid.
       */
      virtual void filter(std::string filter_expr);

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned.
       *
       * \return A buffer_sptr pointing to the buffer read from the wnic.
       */
      virtual buffer_sptr read();

   private:

      /**
       * The datalink type for the frames contained by this file.
       */
      datalink_sptr dl_;

      /**
       * The handle to the packet capture file.
       */
      pcap_t *pcap_;
   };
}

#endif // NET_OFFLINE_WNIC_HPP
