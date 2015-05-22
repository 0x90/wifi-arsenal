/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_ELC_MRR_METRIC_HPP
#define METRICS_ELC_MRR_METRIC_HPP

#include <metrics/abstract_metric.hpp>

namespace metrics {

   /**
    * elc_mrr_metric is the ELC metric augmented with multi-rate retry information..
    */
   class elc_mrr_metric : public abstract_metric {
   public:

      /**
       * elc_mrr_metric constructor.
       *
       * \param cw_time_us The measured contention window size.
       * \param rts_cts_threshold Use RTS/CTS when rts_cts_threshold <= frame size
       */
      elc_mrr_metric(const std::string& name, uint16_t rts_cts_threshold, uint16_t cw_time_us, uint32_t t_dead, uint16_t acktimeout);

      /**
       * elc_metric copy constuctor.
       *
       * \param other The other elc_metric to initialize from.
       */
      elc_mrr_metric(const elc_mrr_metric& other);

      /**
       * elc_metric assignment operator.
       *
       * \param other The other elc_metric to assign from.
       * \return A reference to this elc_metric.
       */
      elc_mrr_metric& operator=(const elc_mrr_metric& other);

      /**
       * elc_mrr_metric destructor.
       */
     virtual ~elc_mrr_metric();

      /**
       * Add a frame to the elc_mrr_metric and update the elc_mrr_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this
       * elc_mrr_metric instance. The clone is allocated on the heap
       * using new and the caller is responsible for ensuring it is
       * deleted.
       *
       * \return A pointer to a new elc_mrr_metric instance.
       */
      virtual elc_mrr_metric *clone() const;

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
       * Compute the time taken to successfully send packet b.
       *
       * \param b A shared_ptr to the buffer containing the L2 frame.
       * \return The time, in microseconds, to transfer this packet.
       */
      double packet_succ_time(net::buffer_sptr b) const;

      /**
       * Compute the time taken by failing to send packet b.
       *
       * \param b A shared_ptr to the buffer containing the L2 frame.
       * \return The time, in microseconds, to transfer this packet.
       */
      double packet_fail_time(net::buffer_sptr b) const;

      /**
       * Compute the time taken to successfully send frame b. This
       * includes inter-frame spacing, acknowledgment and
       * the RTS/CTS if necessary.
       *
       * \param b A shared_ptr to the buffer.
       * \param rate_Kbs The rate the frame was sent at.
       * \return The time, in microseconds, necessary to send the frame.
       */
      double frame_succ_time(net::buffer_sptr b, uint32_t rate_Kbs) const;

      /**
       * Compute the time taken to unsuccessfully send frame b. This
       * includes inter-frame spacing, ACKTIMEOUT and the RTS/CTS if
       * necessary.
       *
       * \param b A shared_ptr to the buffer.
       * \param rate_Kbs The rate the frame was sent at.
       * \return The time, in microseconds, used by the failed exchange.
       */
      double frame_fail_time(net::buffer_sptr b, uint32_t rate_Kbs) const;

   private:

      /**
       * Name for this metric.
       */
      std::string name_;

      /**
       * The RTS/CTS threshold.
       */
      uint16_t rts_cts_threshold_;

      /**
       * The measured contention window time (in microseconds).
       */
      uint16_t cw_time_us_;

      /**
       * The value to use for the ACKTimeout (UINT16_max == use encoding).
       */
      uint16_t acktimeout_;

      /**
       * The dead time (in microseconds).
       */
      uint32_t t_dead_;

      /**
       * The number of successful packet deliveries.
       */
      uint32_t n_pkt_succ_;

      /**
       * The cumulative airtime for successful packet deliveries.
       */
      double t_pkt_succ_;

      /**
       * The cumulative airtime for failed packet deliveries.
       */
      double t_pkt_fail_;

      /**
       * The cumulative size for packets sent on this elc_mrr_metric.
       */
      uint32_t packet_octets_;

      /**
       * The value of the this ELC/MRR metric.
       */
      double mrr_;

   };

}

#endif // METRICS_ELC_MRR_METRIC_HPP
