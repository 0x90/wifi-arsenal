/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_SIMPLE_ELC_METRIC_HPP
#define METRICS_SIMPLE_ELC_METRIC_HPP

#include <metrics/abstract_metric.hpp>

namespace metrics {

   /**
    * simple_elc_metric is the new ELC metric.
    */
   class simple_elc_metric : public abstract_metric {
   public:

      /**
       * simple_elc_metric default constructor.
       *
       * \param cw_time_us The measured contention window size.
       * \param t_dead The dead time (in microseconds).
       */
      simple_elc_metric();

      /**
       * simple_elc_metric copy constuctor.
       *
       * \param other The other simple_elc_metric to initialize from.
       */
      simple_elc_metric(const simple_elc_metric& other);

      /**
       * simple_elc_metric assignment operator.
       *
       * \param other The other simple_elc_metric to assign from.
       * \return A reference to this simple_elc_metric.
       */
      simple_elc_metric& operator=(const simple_elc_metric& other);

      /**
       * simple_elc_metric destructor.
       */
     virtual ~simple_elc_metric();

      /**
       * Add a frame to the simple_elc_metric and update the simple_elc_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this simple_elc_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A pointer to a new simple_elc_metric instance.
       */
      virtual simple_elc_metric *clone() const;

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
       * The cumulative airtime for successful packet deliveries.
       */
      double t_pkt_;

      /**
       * The total number of octets successfully delivered.
       */
      uint32_t packet_octets_;

      /**
       * Stashed value of this metric.
       */
      double elc_;

   };

}

#endif // METRICS_SIMPLE_ELC_METRIC_HPP
