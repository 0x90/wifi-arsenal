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

#ifndef NET_ENCODING_HPP
#define NET_ENCODING_HPP

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <iosfwd>
#include <set>
#include <stdint.h>

namespace net {

   /**
    * Alias for set of transmission rates in units of 1Kb/s.
    */
   typedef std::set<uint32_t> rateset;

   /**
    * Alias for shared_ptr<encoding>.
    */
   typedef boost::shared_ptr<class encoding> encoding_sptr;

   /**
    * encoding is an interface that specifies the timing
    * characteristics of the IEEE 802.11 channel encoding. Concrete
    * subclasses implement this class for 802.11a/g (OFDM), 802.11b/g
    * (DSSS/OFDM) and 802.11b (FHSS+DSSS) encodings.
    */
   class encoding : public boost::noncopyable {
   public:

      /**
       * Return the specified encoding.
       *
       * \param what The name of the encoding to return.
       * \return A non-null pointer to the encoding.
       * \throws invalid_argument_exception When the named encoding isn't recognized.
       */
      static encoding_sptr get(std::string what);

      /**
       * (Virtual) encoding destructor.
       */
      virtual ~encoding();

      /**
       * Return the value of the ACKTimeout for this encoding. The
       * ACKTimeout is defined (IEEE 802.11 (2007) section 9.2.8) to
       * be a SIFS + SlotTime + aPHY-RX-START-Delay.
       *
       * \return A uint16_t specifying the CWMAX value.
       */
      virtual uint16_t ACKTimeout() const = 0;

      /**
       * Return the set of basic rates for this encoding. These are
       * the mandatory rates that must be supported by all stations
       * using this encoding.
       *
       * \return A reference to a set of basic rates in units of
       *         1Kb/s.
       */
      virtual rateset basic_rates() const = 0;

      /**
       * Return the value of CWMIN for this encoding.
       *
       * \return A uint16_t specifying the CWMIN value.
       */
      virtual uint16_t CWMIN() const = 0;

      /**
       * Return the value of CWMAX for this encoding.
       *
       * \return A uint16_t specifying the CWMAX value.
       */
      virtual uint16_t CWMAX() const;

      /**
       * Returns the DCF Inter-Frame Space (DIFS) time under this
       * encoding. By default a DIFS = SIFS + 2 * slot_time.
       */
      virtual uint16_t DIFS() const;

      /**
       * Return the default TX rate for this encoding. This is the
       * rate from the basic rate set which used to send broadcast
       * traffic and frames to stations whose supported data rates are
       * unknown. We expect it to be the lowest rate.
       *
       * \return The default rate in units of 1Kb/s.
       */
      virtual uint32_t default_rate() const;

      /**
       * Tests whether rate_Kbs is a legal rate for this encoding.
       *
       * \param rate_Kbs The rate in units of 1Kb/s.
       * \return true if the rate is legal; otherwise returns false.
       */
      virtual bool is_legal_rate(uint32_t rate_Kbs) const;

      /**
       * Return the name of this encoding.
       *
       * \return A string naming this encoding.
       */
      virtual std::string name() const = 0;

      /**
       * Return the rate used to answer the given frame rate. This is
       * the highest rate in the basic rate set that is less than, or
       * equal to, the specified rate_Kbs.
       *
       * \param data_rate_Kbs The original frame rate in units of 1Kb/s.
       * \return The response data rate in units of 1Kb/s.
       * \throws invalid_argument_exception When rate_Kbs is not in
       *         the supported rate set for this encoding.
       */
      virtual uint32_t response_rate(uint32_t rate_Kbs) const;

      /**
       * Returns the Short Inter-Frame Spacing (SIFS) time for this encoding.
       *
       * \return A uint16_t specifying the SIFS time.
       */
      virtual uint16_t SIFS() const = 0;

      /**
       * Return the slot time used for this encoding.
       */
      virtual uint16_t slot_time() const = 0;

      /**
       * Return the set of supported rates for this encoding. These
       * are all of the rates that may be supported by stations using
       * this encoding.
       *
       * \return A reference to a set of supported rates in units of
       *         1Kb/s.
       */
      virtual rateset supported_rates() const = 0;

      /**
       * Return the airtime (in microseconds) that it would take to
       * send a frame of the given size using this encoding. Note the
       * frame size must include the FCS which is normally removed by
       * banjax.
       *
       * \param frame_sz The size of the frame in octets.
       * \param rate_kbs The data rate in units of 1Kb/s.
       * \param has_short_preamble true if short preamble is used; otherwise false.
       * \throws invalid_argument_exception When rate_Kbs is not
       *         supported using this encoding.
       */
      virtual uint16_t txtime(uint16_t frame_sz, uint32_t rate_Kbs, bool has_short_preamble = false) const = 0;

      /**
       * Write this object in human-readable form to ostream os.
       *
       * \param os A reference to the stream to write to.
       */
      virtual void write(std::ostream& os) const;

   protected:

      /**
       * Default constructor for encoding.
       */
      encoding();

   };

   /**
    * operator to stream a encoding to an ostream.
    *
    * \param os The stream to write to.
    * \param e The encoding to be streamed.
    * \return A reference to the modified ostream.
    */
   inline std::ostream&
   operator<<(std::ostream& os, const encoding& e)
   {
      os << e;
      return os;
   }

}

#endif // NET_ENCODING_HPP
