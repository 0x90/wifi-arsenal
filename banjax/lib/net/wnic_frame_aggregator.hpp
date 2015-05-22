/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 *
 */

#ifndef NET_WNIC_FRAME_AGGREGATOR_HPP
#define NET_WNIC_FRAME_AGGREGATOR_HPP

#include <net/wnic_wrapper.hpp>
#include <dot11/frame.hpp>

#include <deque>

namespace net {

   /**
    * wnic_frame_aggregator is a WNIC wrapper that aggregates frames
    * into packets. This class is a shim to adapt traffics observed
    * from the monitor node into a form suitable for our metric
    * framework.
    */
   class wnic_frame_aggregator : public net::wnic_wrapper {
   public:

      /**
       * wnic_frame_aggregator constructor.
       *
       * \param w A non-NULL pointer to the wnic to wrap.
       * \param ta The MAC address of the sender.
       */
      wnic_frame_aggregator(wnic_sptr w, const net::eui_48& ta);

      /**
       * wnic_frame_aggregator destructor.
       */
      virtual ~wnic_frame_aggregator();

      /**
       * Read from the wnic. In the event of an unrecoverable failure
       * to read from the wnic then a NULL pointer is returned.
       *
       * \return A (possibly NULL) buffer_sptr.
       */
      virtual buffer_sptr read();

   private:

      /**
       * The MAC address of the transmitter station we are monitoring.
       */
      net::eui_48 ta_;

      /**
       * Aggregator state.
       */
      enum State { READING, AGGREGATING, DRAINING } state_;

      /**
       * Sequence number for the current packet.
       */
      uint16_t seq_no_;

      /**
       * First frame in current packet.
       */
      buffer_sptr first_;

      /**
       * Last frame in current packet.
       */
      buffer_sptr last_;

      /**
       * The TXC for the current packet.
       */
      uint8_t txc_;

      /**
       * Frame queue.
       */
      std::deque<buffer_sptr> frames_;

   };

}

#endif // NET_WNIC_FRAME_AGGREGATOR_HPP
