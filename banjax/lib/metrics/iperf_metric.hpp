/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011-2013 NICTA
 *
 */

#ifndef METRICS_IPERF_METRIC_HPP
#define METRICS_IPERF_METRIC_HPP

#include <metrics/metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * iperf_metric computes packets dropped by kernel and other
    * metrics based on the iperf headers. Note thast instances of
    * iperf_metric should be wrapped by an iperf_metric_wrapper.
    */
   class iperf_metric : public metric {
   public:

      /**
       * iperf_metric constructor.
       *
       * \param name A non-NULL pointer to the name of this metric.
       * \param cw If true add avg CW to contention time; otherwise leave alone.
       */
      iperf_metric(const char *name, bool cw);

      /**
       * iperf_metric copy constuctor.
       *
       * \param other The other iperf_metric to initialize from.
       */
      iperf_metric(const iperf_metric& other);

      /**
       * iperf_metric assignment operator.
       *
       * \param other The other iperf_metric to assign from.
       * \return A reference to this iperf_metric.
       */
      iperf_metric& operator=(const iperf_metric& other);

      /**
       * iperf_metric destructor.
       */
      virtual ~iperf_metric();

      /**
       * Add a frame to the iperf_metric and update the iperf_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this iperf_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new iperf_metric instance.
       */
      virtual iperf_metric *clone() const;

      /**
       * Compute the metric.
       *
       * \param time The 64 bit MAC time for the end of the time period.
       * \param delta_us The time (in microseconds) since the start of the time period.
       * \return The value of this metric as a double.
       */
      virtual double compute(uint64_t mactime, uint32_t delta_us);

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
       * The name of this metric.
       */
      std::string name_;

      /**
       * Do we need to adjust for the IFS+contention window.
       */
      bool cw_;

      /**
       * Is the first packet we've seen?
       */
      bool first_;

      /**
       * The sequence number of the last iperf packet.
       */
      uint32_t last_seq_no_;

      /**
       * Total iperf packet time in us seen since last reset().
       */
      uint_least32_t packet_time_;

      /**
       * iperf packets attempted.
       */
      uint32_t packets_attempted_;

      /**
       * iperf packets delivered.
       */
      uint32_t packets_delivered_;

      /**
       * Number of frames dropped by kernel.
       */
      uint32_t packets_dropped_;

      /**
       * The value of this metric (packet time).
       */
      double metric_;

      /**
       * Is the metric valid?
       */
      bool valid_;

      /**
       * Debug info.
       */
      std::string debug_;

   };

}

#endif // METRICS_IPERF_METRIC_HPP
