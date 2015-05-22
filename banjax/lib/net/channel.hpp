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

#ifndef NET_CHANNEL_HPP
#define NET_CHANNEL_HPP

#include <iosfwd>
#include <stdint.h>

namespace net {

   /**
    * An enum defining frequency units. The only reason for this is to
    * allow calling code to explicitly identify the frequency
    * constructor so don't expect to see anything except MHz.
    */
   enum freq_unit { MHz };

   /**
    * channel is a concrete class that represents an IEEE 802.11 radio
    * channel.
    */
   class channel {
   public:

      /**
       * Construct a new channel instance for the given channel number.
       *
       * \param no The channel number.
       * \throws invalid_argument When no is not a valid channel.
       */
      explicit channel(uint16_t no);

      /**
       * Construct a new channel instance for the given frequency.
       *
       * \param freq The channel frequency.
       * \param unit The units in which the frequency is measured (must be MHz).
       * \throws invalid_argument When no is not a valid channel.
       */
      channel(uint16_t freq_MHz, enum freq_unit ignored);

      /**
       * channel copy-constructor. Initialize a new channel instance
       * with the same state as other.
       *
       * \param other A reference to the object to initialize from.
       */
      channel(const channel& other);

      /**
       * channel assignment operator. Assign this channel instance so
       * that it is the same as other.
       *
       * \param other A reference to the object to initialize from.
       */
      channel& operator=(const channel& other);

      /**
       * channel destructor.
       */
      ~channel();

      /**
       * channel equality operator. Compares this channel with rhs
       * and returns true if they represent the same channel;
       * otherwise returns false.
       *
       * \param rhs The channel to compare against (RHS of expr).
       * \return true if the objects are equal; otherwise false.
       */
      bool operator==(const channel& rhs) const;

      /**
       * channel less than comparison operator. Compares this channel
       * with rhs and returns true if this channel is lower in
       * frequency then rhs; otherwise returns false.
       *
       * \param rhs The channel to compare against (RHS of expr).
       * \return true if the this is less than rhs; otherwise false.
       */
      bool operator<(const channel& rhs) const;

      /**
       * Return the centre frequency of the channel in MHz.
       *
       * \return The frequency of the channel in MHz.
       */
      uint16_t freq_MHz() const;

      /**
       * Returns the IEEE 802.11 channel number for this channel.
       *
       * \return The channel number.
       */
      uint16_t number() const;

      /**
       * Return a string describing the band for this channel.
       *
       * \return A pointer to a string describing the band.
       */
      const char *band() const;

      /**
       * Write this object in human-readable form to ostream os.
       *
       * \param os A reference to the stream to write to.
       */
      void write(std::ostream& os) const;

   private:

      /**
       * channel::info is the specification for a channel.
       */
      struct info {
         uint16_t no_;
         uint16_t freq_MHz_;
         const char *band_;
      };
 
      /**
       * The complete list of channel::info objects that banjax knows about.
       */
      static const info INFOS_[];

      /**
       * The channel::info for this channel instance.
       */
      const info *info_;
   };

   /**
    * operator to stream a channel to an ostream.
    *
    * \param os The stream to write to.
    * \param chan The channel to be streamed.
    * \return A reference to the modified ostream.
    */
   std::ostream&
   operator<<(std::ostream& os, const channel& chan);

}

#endif // NET_CHANNEL_HPP
