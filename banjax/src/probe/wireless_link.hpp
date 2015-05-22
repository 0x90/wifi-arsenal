/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright NICTA, 2011
 */

#ifndef ETX_WIRELESS_LINK_HPP
#define ETX_WIRELESS_LINK_HPP

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <stdint.h>

namespace ETX {

	/**
    * wireless_link represents a link between two wireless stations.
    */
   class wireless_link : public boost::noncopyable {
   public:

      /**
       * wireless_link constructor.
       *
       * \param window_sz The size of the receive window.
       */
      explicit wireless_link(uint16_t window_sz);

      /**
       * wireless_link destructor.
       */
      ~wireless_link();

      /**
       * Inform the wireless_link that the clock has ticked and we need to
       * commit the current probe count to the probe window.
       */
      void advance_probe_window();

      /**
       * Notify the wireless_link of the arrival of the probe.
       *
       * \param seq_no The sequence number of the received probe
       */
      void rx_probe(uint32_t seq_no);

      /**
       * Return the number of probes received successfully on this
       * wireless_link during the probe window.
       *
       * \return A uint16_t giving the number of probes received.
       */
      uint16_t rx_probe_count() const;

      /**
       * The size of the rx probe window.
       *
       * \return A uint16_t giving the size of the probe window.
       */
      uint16_t rx_probe_window() const;

      /**
       * Set the transmit delivery ratio for this wireless_link.
       *
       * \param probe_count A uint16_t specifying the number of probes received.
       * \param probe_window A uint16_t specifying the size of the probe window. 
       */
      void tx_delivery_ratio(uint16_t probe_count, uint16_t probe_window);

      /**
       * Return the number of tx_probes delivered successfully on this
       * wireless_link during this tx probe window.
       */
      uint16_t tx_probe_count() const;

      /**
       * The size of the tx probe window.
       *
       * \return A uint16_t giving the size of the tx probe window.
       */
      uint16_t tx_probe_window() const;

   private:

      /**
       * The last sequence number received.
       */
      uint32_t last_seq_no_;

      /**
       * Count of RX probes received in last tick.
       */
      uint16_t rx_probe_count_;

      /**
       * The RX probe window size.
       */
      uint16_t rx_probe_window_;

      /**
       * The maximum size of the RX probe window.
       */
      const uint16_t RX_PROBE_WINDOW_MAX_;

      /**
       * Queue of the RX probes.
       */
      uint16_t *rx_probes_;

      /**
       * Current rx_probes_ insertion point.
       */
      size_t rx_probes_loc_;

      /**
       * The TX probe count.
       */
      uint16_t tx_probe_count_;

      /**
       * The TX probe window size.
       */
      uint16_t tx_probe_window_;

   };

   /**
    * Alias for shared_ptr<wireless_link>.
    */
   typedef boost::shared_ptr<wireless_link> wireless_link_sptr;

}

#endif // ETX_WIRELESS_LINK_HPP
