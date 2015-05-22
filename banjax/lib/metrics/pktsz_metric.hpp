/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_PKTSZ_METRIC_HPP
#define METRICS_PKTSZ_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * pktsz_metric reports the average iperf packet size.
    */
   class pktsz_metric : public abstract_metric {
   public:

      /**
       * pktsz_metric default constructor.
       *
       * \param enc The encoding used.
       */
      pktsz_metric();

      /**
       * pktsz_metric copy constuctor.
       *
       * \param other The other pktsz_metric to initialize from.
       */
      pktsz_metric(const pktsz_metric& other);

      /**
       * pktsz_metric assignment operator.
       *
       * \param other The other pktsz_metric to assign from.
       * \return A reference to this pktsz_metric.
       */
      pktsz_metric& operator=(const pktsz_metric& other);

      /**
       * pktsz_metric destructor.
       */
     virtual ~pktsz_metric();

      /**
       * Add a frame to the pktsz_metric and update the pktsz_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this pktsz_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new pktsz_metric instance.
       */
      virtual pktsz_metric *clone() const;

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
       * The average packet size for this metric.
       */
      double pktsz_;

   };

}

#endif // METRICS_PKTSZ_METRIC_HPP
