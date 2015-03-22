/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#ifndef NET_OFDM_ENCODING_HPP
#define NET_OFDM_ENCODING_HPP

#include <net/encoding.hpp>

#include <iosfwd>
#include <stdint.h>

namespace net {

   /**
    * ofdm_encoding is a specification class that defines the timing
    * characteristics for the IEEE 802.11a/g OFDM channel
    * encoding. Timing characteristics can be found in table 17-15 of
    * IEEE 802.11 (2007) and the TXTIME calculation in section 17.4.3.
    */
   class ofdm_encoding : public encoding {
   public:

      /**
       * Return a pointer to an instance of this class.
       *
       * \return An encoding_sptr pointing to an ofdm_encoding instance.
       */
      static encoding_sptr get();

      /**
       * (Virtual) ofdm_encoding destructor.
       */
      virtual ~ofdm_encoding();

      /**
       * Return the value of the ACKTimeout for this encoding. The
       * ACKTimeout is defined (IEEE 802.11 (2007) section 9.2.8) to
       * be a SIFS + SlotTime + aPHY-RX-START-Delay.
       *
       * \return A uint16_t specifying the CWMAX value.
       */
      virtual uint16_t ACKTimeout() const;

      /**
       * Return the set of basic rates for this encoding. These are
       * the mandatory rates that must be supported by all stations
       * using this encoding.
       *
       * \return A set of the basic rates in units of 1Kb/s.
       */
      virtual rateset basic_rates() const;

      /**
       * Return the value of CWMIN for this encoding.
       *
       * \return A uint16_t specifying the CWMIN value.
       */
      virtual uint16_t CWMIN() const;

      /**
       * Return the name of this encoding.
       *
       * \return A string naming this encoding.
       */
      virtual std::string name() const;

      /**
       * Returns the Short Inter-Frame Spacing (SIFS) time for the
       * OFDM encoding.
       *
       * \return A uint16_t specifying the SIFS time.
       */
      virtual uint16_t SIFS() const;

      /**
       * Return the slot time used for this ofdm_encoding.
       */
      virtual uint16_t slot_time() const;

      /**
       * Return the set of supported rates for this encoding. These
       * are all of the rates that may be supported by stations using
       * this encoding.
       *
       * \return A set of supported rates in units of 1Kb/s.
       */
      virtual rateset supported_rates() const;

      /**
       * Return the airtime (in microseconds) that it would take to
       * send a frame of the given size using the OFDM encoding. Note
       * the frame size must include the FCS which is normally removed
       * by banjax.
       *
       * \param frame_sz The size of the frame in octets.
       * \param rate_kbs The data rate in units of 1Kb/s.
       * \param ignored The OFDM encoding does not support short preambles.
       * \returns The time, in microseconds, needed to send the frame.
       * \throws invalid_argument_exception When rate_Kbs is not permitted using this encoding.
       */
      virtual uint16_t txtime(uint16_t frame_sz, uint32_t rate_Kbs, bool ignored) const;

   private:

      /**
       * Default constructor for ofdm_encoding.
       */
      ofdm_encoding();

   };

}

#endif // NET_OFDM_ENCODING_HPP
