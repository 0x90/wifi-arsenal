/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2011 Steve Glass
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

#ifndef NET_WNIC_WRAPPER_HPP
#define NET_WNIC_WRAPPER_HPP

#include <net/wnic.hpp>

namespace net {

   /**
    * wnic_wrapper are wnic implementations that perform pre- and
    * post-processing for another wnic implementation.
    */
   class wnic_wrapper : public wnic {
   public:

      /**
       * Virtual destructor for the wnic_wrapper class.
       */
      virtual ~wnic_wrapper();

      /**
       * Return an integer specifying the datalink type used by this
       * wnic.
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
       * Return the name of this wnic device.
       *
       * \return A string naming this wnic.
       */
      virtual std::string name() const;

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned.
       *
       * \return A (possibly NULL) buffer_sptr.
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
       * wnic_wrapper constructor.
       *
       * \param wnic A non-NULL wnic_sptr pointing to the wrapped wnic.
       */
      explicit wnic_wrapper(wnic_sptr wnic);

   protected:

      /**
       * Pointer to the wrapped wnic.
       */
      wnic_sptr wnic_;

   };

}

#endif // NET_WNIC_WRAPPER_HPP
