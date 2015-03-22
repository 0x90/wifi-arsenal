/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_LEGACY_ELC_METRIC_HPP
#define METRICS_LEGACY_ELC_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * legacy_elc_metric is the ELC metric from Jono's original paper.
    */
   class legacy_elc_metric : public abstract_metric {
   public:

      /**
       * legacy_elc_metric constructor.
       *
       * \param enc The encoding used.
       * \rate_kbs The maximum link rate (used to compute TMT).
       * \param mpdu_sz_ The MTU size to use in computing ELC.
       * \param rts_cts_threshold The frame size above which we need to use RTS/CTS.
       */
      legacy_elc_metric(net::encoding_sptr enc, uint32_t rate_kbs, uint16_t mpdu_sz,  uint16_t rts_cts_threshold);

      /**
       * legacy_elc_metric copy constuctor.
       *
       * \param other The other legacy_elc_metric to initialize from.
       */
      legacy_elc_metric(const legacy_elc_metric& other);

      /**
       * legacy_elc_metric assignment operator.
       *
       * \param other The other legacy_elc_metric to assign from.
       * \return A reference to this legacy_elc_metric.
       */
      legacy_elc_metric& operator=(const legacy_elc_metric& other);

      /**
       * legacy_elc_metric destructor.
       */
      virtual ~legacy_elc_metric();

      /**
       * Add a frame to the legacy_elc_metric and update the legacy_elc_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this legacy_elc_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new legacy_elc_metric instance.
       */
      virtual legacy_elc_metric *clone() const;

      /**
       * Compute the metric.
       *
       * \param delta_us The time (in microseconds) over which to compute the metric.
       * \return The value of this metric as a double.
       */
      virtual double compute(uint32_t delta_us);

      /**
       * Reset the internal state of the metric.
       */
      virtual void reset();

      /**
       * Write this object in human-readable form to ostream os.
       *
       * \param os A reference to the stream to write to.
       */
      virtual void write(std::ostream& os) const;

   private:

      /**
       * Scan the standard rateset of the default encoding and return
       * the value which has the smallest difference to r.
       *
       * \param r The rate to find.
       * \return The value in rates which is closest to r.
       */
      uint32_t closest_rate(uint32_t r) const;

      /**
       * Compute the time it would take to successfully send a frame
       * of the given size at the specified rate. The time includes
       * the contention, RTS/CTS, interframe spacing and
       * acknowledgment.
       *
       * \param rate_kbs The rate in units of kbs.
       * \param frame_sz The size of the frame in octets.
       * \return The time taken (in microseconds).
       */
      uint32_t successful_tx_time(uint32_t rate_kbs, uint16_t packet_sz) const;

   private:

      /**
       * The encoding used to compute the metric.
       */
      net::encoding_sptr enc_;

      /**
       * The size of the MPDU to use when computing the metric.
       */
      uint16_t mpdu_sz_;

      /**
       * The RTS/CTS threshold.
       */
      uint16_t rts_cts_threshold_;

      /**
       * The total number of frame transmission attempts.
       */
      uint32_t frames_attempted_;

      /**
       * The total number of octets sent.
       */
      uint_least32_t frames_attempted_octets_;

      /**
       * The total number of successfully delivered frames.
       */
      uint32_t frames_delivered_;

      /**
       * The total number of successfully delivered octets.
       */
      uint_least32_t frames_delivered_octets_;

      /**
       * Sum of the data rates used to send packets (used to compute average).
       */
      uint_least32_t rates_kbs_sum_;

      /**
       * The link rate (used to calculate TMT).
       */
      uint32_t rate_kbs_;

      /**
       * The current value for "classic" ELC using TMT.
       */
      double classic_elc_;

      /**
       * The current value of this legacy ELC metric.
       */
      double elc_;

   };

}

#endif // METRICS_LEGACY_ELC_METRIC_HPP
