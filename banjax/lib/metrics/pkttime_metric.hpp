/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 *
 */

#ifndef METRICS_PKTTIME_METRIC_HPP
#define METRICS_PKTTIME_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * pkttime_metric reports the average packet time for a saturated
    * link. Note that this is ONLY accurate for a completely saturated
    * link as it divides the time by the number of packets delivered.
    */
   class pkttime_metric : public abstract_metric {
   public:

      /**
       * pkttime_metric default constructor.
       *
       * \param enc The encoding used.
       */
      pkttime_metric();

      /**
       * pkttime_metric copy constuctor.
       *
       * \param other The other pkttime_metric to initialize from.
       */
      pkttime_metric(const pkttime_metric& other);

      /**
       * pkttime_metric assignment operator.
       *
       * \param other The other pkttime_metric to assign from.
       * \return A reference to this pkttime_metric.
       */
      pkttime_metric& operator=(const pkttime_metric& other);

      /**
       * pkttime_metric destructor.
       */
     virtual ~pkttime_metric();

      /**
       * Add a frame to the pkttime_metric and update the pkttime_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this pkttime_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new pkttime_metric instance.
       */
      virtual pkttime_metric *clone() const;

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
       * The total number of successful packet deliveries.
       */
      uint_least32_t packets_;

      /**
       * The total size of all successful packet deliveries.
       */
      uint_least32_t octets_;

      /**
       * The average packet time for this metric.
       */
      double pkttime_;

      /**
       * Can we compute a valid metric?
       */
      bool valid_;

   };

}

#endif // METRICS_PKTTIME_METRIC_HPP
