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

#ifndef NET_ABSTRACT_WNIC_HPP
#define NET_ABSTRACT_WNIC_HPP

#include <net/wnic.hpp>

namespace net {

   /**
    * Default implementation of the wnic interface.
    */
   class abstract_wnic : public wnic {
   public:

      /**
       * Virtual destructor for the abstract_wnic class.
       */
      virtual ~abstract_wnic();

      /**
       * Return the name of this wnic device.
       *
       * \return A string naming this wnic.
       */
      virtual std::string name() const;

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned. In this implementation
       *
       * \return A buffer_sptr pointing to the buffer read from the wnic.
       */
      virtual buffer_sptr read();

      /**
       * Writes a buffer to a wnic.
       *
       * \param buf A reference to the buffer to write.
       */
      virtual void write(const buffer& b);

   protected:

      /**
       * Default constructor for the wnic object.
       */
      explicit abstract_wnic(const std::string& dev_name);

   private:

      /**
       * A string identifying this wnic.
       */
      std::string name_;

   };

}

#endif // NET_ABSTRACT_WNIC_HPP
