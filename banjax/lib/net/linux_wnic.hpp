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

#ifdef __linux__

#ifndef NET_LINUX_WNIC_HPP
#define NET_LINUX_WNIC_HPP

#include <boost/noncopyable.hpp>
#include <net/abstract_wnic.hpp>

namespace net {

   /**
    * An 802.11 wireless network interface. This implementation
    * expects to talk to devices that are implemented by the GNU/Linux
    * wireless stack.
    */
   class linux_wnic : public abstract_wnic {
   public:

      /**
       * Constructs a new linux_wnic instance.
       *
       * \param name The name of the device.
       */
      explicit linux_wnic(std::string name);

      /**
       * Virtual destructor for the wnic class.
       */
      virtual ~linux_wnic();

      /**
       * Return an integer specifying the wnic's datalink type.
       *
       * \return An integer encoding the datalink type.
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

      /**
       * Writes a buffer to a wnic.
       *
       * \param buf A reference to the buffer to write.
       */
      virtual void write(const buffer& buf);

   protected:

      /**
       * Return the ARP type for this datalink. Converts between the
       * ARPHRD_* and DLT_* worldnamespaces and raises an
       * invalid_argument exception if an unssupported ARP type is in
       * use.
       *
       * \param arp_type The GNU/Linux ARP type. 
       * \return An int encoding the wnic's datalink type.
       * \throws illegal_argument when the arp_type is not supported.
       */
      virtual int datalink_type(int arp_type) const;

   private:

      /**
       * Perform an ioctl on the socket.
       *
       * \param ioctl_no
       * \param data 
       */
      template <class T> int dev_ioctl(int ioctl_no, T& data) const;

   private:

      /**
       * Socket descriptor for the raw wnic device.
       */
      int socket_;

      /**
       * Pointer to the datalink.
       */
      datalink_sptr dl_;

   };
}

#endif // NET_LINUX_WNIC_HPP

#endif // __linux__
