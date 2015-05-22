/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2008-2011 Steve Glass
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

#ifndef NET_WNIC_HPP
#define NET_WNIC_HPP

#include <net/buffer.hpp>
#include <net/datalink.hpp>

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <string>

namespace net {

   /**
    * Alias for boost::shared_ptr<wnic>.
    */
   typedef boost::shared_ptr<class wnic> wnic_sptr;

   /**
    * The interface to IEEE 802.11 wireless network devices.
    */
   class wnic : public boost::noncopyable {
   public:

      /**
       * Open the wnic identified by name - either a device name for
       * physical WNICs or the pathname for a tcpdump-format ".pcap"
       * file. A physical device name ending with "+r", "+w" or "+rw"
       * will be decorated by an appropriate wnic_wrapper that logs
       * all reads and/or writes from the wnic to a packet capture
       * file.
       *
       * \param name A string naming the wnic.
       * \return A wnic_sptr pointing to the wnic.
       */
      static wnic_sptr open(std::string name);

      /**
       * Virtual destructor for the wnic class.
       */
      virtual ~wnic();

      /**
       * Return an integer specifying the datalink type used by this
       * wnic.
       *
       * \return An integer encoding the datalink type.
       */
      virtual int datalink_type() const = 0;

      /**
       * Install the capture filter given by filter_expr. See
       * pcap-filter(7) for details of the filter_expr syntax.
       *
       * \param filter_expr The filter expression.
       * \throws invalid_argument If expr is not valid.
       */
      virtual void filter(std::string filter_expr) = 0;

      /**
       * Return the name of this wnic device.
       *
       * \return A string naming this wnic.
       */
      virtual std::string name() const = 0;

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned.
       *
       * \return A buffer_sptr pointing to the buffer read from the wnic.
       */
      virtual buffer_sptr read() = 0;

      /**
       * Writes a buffer to a wnic.
       *
       * \param b A reference to the buffer to write.
       */
      virtual void write(const buffer& b) = 0;

   protected:

      /**
       * Default constructor for the wnic object.
       */
      wnic();

   };

}

#endif // NET_WNIC_HPP
