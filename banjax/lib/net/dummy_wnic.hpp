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

#ifndef NET_DUMMY_WNIC_HPP
#define NET_DUMMY_WNIC_HPP

#include <net/abstract_wnic.hpp>

namespace net {

	/**
    * dummy_wnic is wnic implementation that does nothing.
    */
   class dummy_wnic : public abstract_wnic {
   public:

      /**
       * Construct a dummy_wnic instance.
       *
       * \param dev_name The name of the device.
       * \param dlt The ARP type for this wnic.
       */
      dummy_wnic(std::string dev_name, int dlt);

      /**
       * dummy_wnic virtual destructor.
       */
      virtual ~dummy_wnic();

      /**
       * Return an integer specifying the datalink type used by this
       * wnic. This is a protected method so other wnics can call it
       * without it being part of the public interface for wnic.
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

   private:

      int dlt_;

   };

}

#endif // NET_DUMMY_WNIC_HPP
