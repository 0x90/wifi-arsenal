/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2013 Steve Glass
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

#ifndef NET_EUI_48_HPP
#define NET_EUI_48_HPP

#include <cstddef>
#include <iosfwd>
#include <stdint.h>

namespace net {

   /**
    * Global defining size of an eui_48 MAC address in octets.
    */
   const size_t MAC_SZ = 6;

   /**
    * A MAC address. See <a
    * href="http://standards.ieee.org/getieee802/download/802-2001.pdf">
    * the IEEE EUI-48 (Extended Universal Identifier/48 bit)
    * standard</a> for details.
    */
   class eui_48 {
   public:

      /**
       * eui_48 default constructor. Initializes this MAC address to
       * the broadcasdt address (ff:ff:ff:ff:ff:ff).
       */
      eui_48();

      /**
       * eui_48 constructor. Creates a new mac address instance from
       * the address specified by mac_str.
       *
       * \param mac_str The mac address string.
       * \param sep The separator character (either ':' or '-').
       * \throws invalid_argument When sep is invalid or mac_str cannot be parsed.
       */
      explicit eui_48(const char *mac_str, char sep=':');

      /**
       * eui_48 constructor. Creates a new eui_48 instance from the
       * address given by mac.
       *
       * \param mac_sz Should always be MAC_SZ.
       * \param mac_str The mac address string.
       * \throws invalid_argument When mac_sz is not MAC_SZ or mac is NULL.
       */
      eui_48(size_t mac_sz, const uint8_t *mac);

      /**
       * eui_48 copy-constructor. Initialize a new eui_48 instance
       * with the same state as other.
       *
       * \param other A reference to the object to initialize from.
       */
      eui_48(const eui_48& other);

      /**
       * eui_48 assignment operator. Assign this eui_48 instance so
       * that it has the same value as other.
       *
       * \param other A reference to the object to initialize from.
       */
      eui_48& operator=(const eui_48& other);

      /**
       * eui_48 destructor.
       */
     ~eui_48();

      /**
       * eui_48 equality comparison operator. Compares this MAC
       * address with rhs and returns true if this is equal to rhs;
       * otherwise returns false.
       *
       * \param rhs The eui_48 to compare against (RHS of expr).
       * \return true if the this is less than rhs; otherwise false.
       */
      bool operator==(const eui_48& rhs) const;

      /**
       * eui_48 less than comparison operator. Compares this MAC
       * address with rhs and returns true if this is smaller than
       * rhs; otherwise returns false.
       *
       * \param rhs The eui_48 to compare against (RHS of expr).
       * \return true if the this is less than rhs; otherwise false.
       */
      bool operator<(const eui_48& rhs) const;

      /**
       * eui_48 bitwise AND operator. Computes the bitwise AND of this
       * MAC address with rhs and returns the result.
       *
       * \param rhs The eui_48 to bitwise AND against.
       * \return An eui_48 representing the result.
       */
      eui_48 operator&(const eui_48& rhs);

      /**
       * Return a pointer to the MAC address.
       *
       * \return A non-null pointer to the internal form of the buffer.
       */
      const uint8_t *data() const;

      /**
       * Return the size of this eui_48 instance in octets. This will
       * always be MAC_SZ but is provided to avoid polluting calling
       * code with that constant.
       *
       * \return The size of the eui_48 (MAC_SZ).
       */
      size_t data_size() const;

      /**
       * Compute a hash value for this eui_48 instance.
       *
       * \return A size_t containing the hash value.
       */
      std::size_t hash() const;

      /**
       * Return true iff this eui_48 instance represents a multicast
       * address. These addresses have bit0 set of the most
       * significant octet and are easily detected.
       *
       * \return true if this is a multicast address; otherwise false.
       */
      bool is_multicast() const;

      /**
       * Return true iff this eui_48 instance represents a special
       * address. Special addresses are not assigned to adapters but
       * are reserved by specific protocols. In other words, a special
       * address does not uniquely identify a station.
       *
       * \true if this is a special address; otherwise false.
       */
      bool is_special() const;

      /**
       * Return true iff this eui_48 instance represents a unicast
       * address. These addresses have bit0 cleared for the most
       * significant octet and are easily detected. This is the
       * logical negation of is_multicast().
       *
       * \return true if this is a multicast address; otherwise false.
       */
      bool is_unicast() const;

      /**
       * Write this object in human-readable form to ostream os.
       *
       * \param os A reference to the stream to write to.
       */
      void write(std::ostream& os) const;

   private:

      /**
       * The internal storage for the MAC address.
       */
      uint8_t addr_[MAC_SZ];

   };
   
   /**
    * Returns the hash value for the specified eui_48 object.
    *
    * \param addr A const-reference to the object to hash.
    * \param A size_t containing the hash value.
    */
   size_t hash(const eui_48& addr);

   /**
    * operator to stream an eui_48 MAC address to an ostream.
    *
    * \param os The stream to write to.
    * \param addr The address to be streamed.
    * \return A reference to the modified ostream.
    */
   std::ostream& operator<<(std::ostream& os, const eui_48& addr);

}

#endif // NET_EUI_48_HPP
