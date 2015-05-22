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

#ifndef NET_BUFFER_INFO_HPP
#define NET_BUFFER_INFO_HPP

#include <net/encoding.hpp>

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <stdint.h>
#include <iosfwd>
#include <vector>

namespace net {

   /**
    * Property label type.
    */
   typedef uint32_t property_t;

   /* Property labels.
    */
   const property_t CHANNEL_FLAGS         = 0x0001;
   const property_t DATA_RETRIES          = 0x0002;
   const property_t FREQ_MHz              = 0x0004;
   const property_t RATE_Kbs              = 0x0010;
   const property_t RATES_Kbs             = 0x0020;
   const property_t RTS_RETRIES           = 0x0040;
   const property_t RX_FLAGS              = 0x0080;
   const property_t SIGNAL_dBm            = 0x0100;
   const property_t TIMESTAMP1            = 0x0200;
   const property_t TIMESTAMP2            = 0x0400;
   const property_t TIMESTAMP_WALLCLOCK   = 0x0800;
   const property_t TX_FLAGS              = 0x1000;
   const property_t METRIC                = 0x2000;
   const property_t PACKET_TIME           = TIMESTAMP1 | TIMESTAMP2;

   /**
    * Property value type.
    */
   typedef uint32_t flags_t;

   /* Channel encoding flags.
    */
   const flags_t CHANNEL_CODING_DSSS     = 0x0001;
   const flags_t CHANNEL_CODING_DYNAMIC  = 0x0002;
   const flags_t CHANNEL_CODING_FHSS     = 0x0004;
   const flags_t CHANNEL_CODING_OFDM     = 0x0008;
   const flags_t CHANNEL_PREAMBLE_LONG   = 0x0010;
   const flags_t CHANNEL_PREAMBLE_SHORT  = 0x0020;
   const flags_t CHANNEL_RATE_FULL       = 0x0040;
   const flags_t CHANNEL_RATE_HALF       = 0x0080;
   const flags_t CHANNEL_RATE_QUARTER    = 0x0100;
   
   /* RX flags.
    */
   const flags_t RX_FLAGS_BAD_FCS        = 0x0001;

   /* TX flags.
    */
   const flags_t TX_FLAGS_FAIL           = 0x0001;

   /**
    * buffer_info is a concrete, leaf class that provides meta
    * information for a buffer. All of the properties are optional and
    * user code must take care to check (using #has()) whether the
    * desired properties are available.
    */
   class buffer_info : public boost::noncopyable {
   public:

      /**
       * buffer_info default constructor.
       */
      buffer_info();

      /**
       * buffer_info destructor.
       */
      ~buffer_info();

      /**
       * Clears the specified properties from this buffer_info.
       *
       * \param props The properties to be cleared.
       */
      void clear(property_t props = ~0);

      /**
       * Test whether the specified properties are available. Note
       * that you can test for the presence of multiple properties by
       * combining them with the bitwise or operator ('|').
       *
       * \param props The properties to test.
       * \return bool true if the specified properties are present.
       */
      bool has(property_t props) const;

      /**
       * Returns the channel encoding used by this frame. This is a
       * convenience function that uses the rx_flags to construct the
       * correct kind of encoding. The rx_flags must be present or a
       * logic_error exception will be raised.
       *
       * \returns A (possibly null) encoding_sptr.
       */
      encoding_sptr channel_encoding() const;

      /**
       * Return the channel encoding flags.
       *|
       * \return A flags_t containing the channel encoding flags.
       */
      flags_t channel_flags() const;

      /**
       * Sets the channel encoding flags.
       *|
       * \param f A flags_t containing the new channel encoding flags.
       */
      void channel_flags(flags_t f);

      /**
       * Returns the number of times the data frame is re-transmitted.
       *
       * \return A uint8_t specifying the re-transmission count.
       * \throws runtime_error When the property is not present.
       */
      uint8_t data_retries() const;

      /**
       * Sets the number of time the data frame is re-transmitted.
       *
       * \param r A uint8_t specifying the re-transmission count.
       */
      void data_retries(uint8_t r);

      /**
       * Returns the frequency in MHz at which this frame is transmitted.
       *
       * \return The frequency (in units of 1MHz).
       */
      uint32_t freq_MHz() const;

      /**
       * Sets the frequency in MHz at which this frame is transmitted.
       *
       * \param f The frequency (in units of 1MHz).
       */
      void freq_MHz(uint32_t f);

      /**
       * Returns the data rate in units of Kb/s.
       *
       * \return A uint32_t specifying the data rate in Kb/s.
       */
      uint32_t rate_Kbs() const;

      /**
       * Sets the data rate in units of Kb/s.
       *
       * \param r A uint32_t specifying the data rate in Kb/s.
       */
      void rate_Kbs(uint32_t r);

      /**
       * Return the count of RTS retries.
       *
       * \return A uint8_t containing the RTS retry count.
       */
      uint8_t rts_retries() const;

      /**
       * Sets the count of RTS retries.
       *
       * \param r A uint8_t containing the RTS retry count.
       */
      void rts_retries(uint8_t r);

      /**
       * Return the RX flags.
       *
       * \return A flags_t containing the RX flags.
       */
      flags_t rx_flags() const;

      /**
       * Sets the RX flags.
       *
       * \param f A flags_t containing the RX flags.
       */
      void rx_flags(flags_t f);

      /**
       * Returns the RSSI in units of dBm.
       *
       * \return The RSSI in dBm.
       */
      int8_t signal_dBm() const;

      /**
       * Sets the RSSI in units of dBm.
       *
       * \param s The RSSI in dBm.
       */
      void signal_dBm(int8_t s);

      /**
       * Return the timestamp1 value. This represents the time when
       * the frame begins to arrive at the receiver.
       *
       * \return A uint64_t containing the timestamp1.
       */
      uint64_t timestamp1() const;

      /**
       * Sets the timestamp1 value. This represents the time when the
       * frame begins to arrive at the receiver.
       *
       * \param t A uint64_t containing the timestamp1.
       */
      void timestamp1(uint64_t t);

      /**
       * Return the timestamp2 value. This represents the time when
       * the frame stops at the receiver.
       *
       * \return A uint64_t containing the timestamp2.
       */
      uint64_t timestamp2() const;

      /**
       * Sets the timestamp2 value. This represents the time when the
       * frame begins to arrive at the receiver.
       *
       * \param t A uint64_t containing the timestamp2.
       */
      void timestamp2(uint64_t t);

      /**
       * Return the wallclock time for the arrival of this frame. This
       * value has limited resolution.
       *
       * \return A uint64_t containing the wallclock timestamp.
       */
      uint64_t timestamp_wallclock() const;

      /**
       * Sets the wallclock time for the arrival of this frame. This
       * value has limited resolution.
       *
       * \param t A uint64_t containing the wallclock timestamp.
       */
      void timestamp_wallclock(uint64_t t);

      /**
       * Return the TX flags.
       *
       * \return A flags_t containing the TX flags.
       */
      flags_t tx_flags() const;

      /**
       * Sets the TX flags.
       *
       * \param f A flags_t containing the TX flags.
       */
      void tx_flags(flags_t f);

      /**
       * Write this buffer info to an output stream.
       *
       * \param os A reference to the ostream to write to.
       */
      void write(std::ostream& os) const;

      // Warning: proprietary extension!

      /**
       * Returns a vector of transmission rates for the frame. 
       *
       * \return A vector<uint32_t> containing the rates in Kb/s.
       */
      std::vector<uint32_t> rates() const;

      /**
       * Set the rate vector to the specified value.
       *
       * \param rates The vector<uint32_t> of transmission rates in Kb/s.
       */
      void rates(const std::vector<uint32_t>& rates);

      /**
       * Return the elapsed time taken to transmit this packet.
       *
       * \return The time (in microseconds) used to send this packet.
       */
      uint32_t packet_time() const;

      /**
       * Return the link metric value for this packet.
       *
       * \return A uint32_t containing the metric.
       */
      uint32_t metric() const;

      /**
       * Set the link metric value for this packet.
       *
       * \param m A uint32_t containing the metric.
       */
      void metric(uint32_t m);

   private:

      /**
       * Return the bit number for the given property. prop must be
       * one of the legitimate properties or an invalid_argument
       * exception will be raised.
       *
       * \param prop The property.
       * \return The bit number for that property.
       */
      uint8_t bit(property_t prop) const;

   private:

      /**
       * Which properties are actually present?
       */
      property_t present_;

      /**
       * The channel coding flags.
       */
      flags_t channel_flags_;

      /**
       * The number of times the data frame is retried.
       */
      uint8_t data_retries_;

      /**
       * Frequency in MHz.
       */
      uint32_t freq_MHz_;

      /**
       * Rate in Kb/s.
       */
      uint32_t rate_Kbs_;

      /**
       * Number of RTS retries.
       */
      uint8_t rts_retries_;

      /**
       * RX flags.
       */
      flags_t rx_flags_;

      /**
       * RSSI in dBm.
       */
      uint8_t signal_dBm_;

      /**
       * Timestamp of beginning of frame in microseconds.
       */
      uint64_t timestamp1_;

      /**
       * Timestamp of end of frame in microseconds.
       */
      uint64_t timestamp2_;

      /**
       * Timestamp for frame arrival in microseconds.
       */
      uint64_t timestamp_wallclock_;

      /**
       * TX flags.
       */
      flags_t tx_flags_;

      /**
       * Rates.
       */
      std::vector<uint32_t> rates_;

      /**
       * The link metric as it was when the kernel sent this packet.
       */
      uint32_t metric_;

   };

   /**
    * operator to stream a buffer_info to an ostream.
    *
    * \param os The stream to write to.
    * \param info The buffer_info to be streamed.
    * \return A reference to the modified ostream.
    */
   std::ostream& operator<<(std::ostream& os, const buffer_info& info);

   /**
    * Alias for shared_ptr<buffer_info>.
    */
   typedef boost::shared_ptr<net::buffer_info> buffer_info_sptr;

   /**
    * Alias for shared_ptr<const buffer_info>.
    */
   typedef boost::shared_ptr<const net::buffer_info> const_buffer_info_sptr;

}

#endif // NET_BUFFER_INFO_HPP
