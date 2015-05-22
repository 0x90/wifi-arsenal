/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_TMT_METRIC_HPP
#define METRICS_TMT_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * tmt_metric is the TMT value from Jun's paper (except we compute
    * it correctly !^).
    */
   class tmt_metric : public abstract_metric {
   public:

      /**
       * tmt_metric constructor.
       *
       * \param enc The encoding used.
       * \rate_kbs The maximum link rate (used to compute TMT).
       * \param mpdu_sz_ The MTU size to use in computing ELC.
       * \param rts_cts_threshold The frame size above which we need to use RTS/CTS.
       */
      tmt_metric(net::encoding_sptr enc, uint32_t rate_kbs, uint16_t mpdu_sz,  uint16_t rts_cts_threshold);

      /**
       * tmt_metric copy constuctor.
       *
       * \param other The other tmt_metric to initialize from.
       */
      tmt_metric(const tmt_metric& other);

      /**
       * tmt_metric assignment operator.
       *
       * \param other The other tmt_metric to assign from.
       * \return A reference to this tmt_metric.
       */
      tmt_metric& operator=(const tmt_metric& other);

      /**
       * tmt_metric destructor.
       */
      virtual ~tmt_metric();

      /**
       * Add a frame to the tmt_metric and update the tmt_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this tmt_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new tmt_metric instance.
       */
      virtual tmt_metric *clone() const;

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
       * Compute the time it would take to successfully send a frame
       * of the given size at the specified rate. The time includes
       * the contention, RTS/CTS, interframe spacing and
       * acknowledgment.
       *
       * \param enc The encoding used.
       * \param rate_kbs The rate in units of kbs.
       * \param frame_sz The size of the frame in octets.
       * \return The time taken (in microseconds).
       */
      uint32_t successful_tx_time(net::encoding_sptr enc, uint32_t rate_kbs, uint16_t frame_sz, uint16_t rts_cts_threshold) const;

   private:

      /**
       * The  value of this legacy ELC metric.
       */
      double tmt_;

      /**
       * Any additional debug info we may want to print.
       */
      std::string debug_;

   };

}

#endif // METRICS_TMT_METRIC_HPP
