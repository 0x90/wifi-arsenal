/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_ETX_METRIC_HPP
#define METRICS_ETX_METRIC_HPP

#include <metrics/metric.hpp>

#include <deque>

namespace metrics {

   /**
    * etx_metric estimated transmission count metric.
    */
   class etx_metric : public metric {
   public:

      /**
       * etx_metric constructor.
       * 
       * \param probe_port The port number used for ETX probes.
       * \param window_sz The size of the probe window (in seconds).
       */
      etx_metric(uint16_t probe_port, uint16_t window_sz);

      /**
       * etx_metric copy constuctor.
       *
       * \param other The other etx_metric to initialize from.
       */
      etx_metric(const etx_metric& other);

      /**
       * etx_metric assignment operator.
       *
       * \param other The other etx_metric to assign from.
       * \return A reference to this etx_metric.
       */
      etx_metric& operator=(const etx_metric& other);

      /**
       * etx_metric destructor.
       */
     virtual ~etx_metric();

      /**
       * Add a frame to the etx_metric and update the etx_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this etx_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new etx_metric instance.
       */
      virtual etx_metric *clone() const;

      /**
       * Compute the metric.
       *
       * \param mactime The MAC time (in microseconds) for the end of the time period.
       * \param delta_us The time (in microseconds) over which to compute the metric.
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
       * The port on which we're sending probe packets.
       */
      uint32_t probe_port_;

      /**
       * The size (in microseconds) for the probe window.
       */
      uint32_t window_sz_;

      /**
       * Vector of probe arrival times.
       */
      std::deque<net::buffer_sptr> rx_probes_;

      /**
       * The stashed value of the ETX metric.
       */
      double etx_;

      /**
       * The sequence number of the last packet received. Used only to
       * eliminate duplicate transmissions of the same packet.
       */
      uint32_t seq_no_;

   };

}

#endif // METRICS_ETX_METRIC_HPP
