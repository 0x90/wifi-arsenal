/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_AIRTIME_METRIC_MEASURED_HPP
#define METRICS_AIRTIME_METRIC_MEASURED_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <map>

namespace metrics {

   /**
    * airtime_metric_measured is defined by 802.11s as its default
    * routing metric (see IEEE 802.11s-d8 s 11A.7).
    *
    * This version is based on the Linux kernel implementation found
    * in net/mac80211/mesh_hwmp.c.
    */
   class airtime_metric_measured : public abstract_metric {
   public:

      /**
       * airtime_metric_measured constructor.
       *
       * \param name The name this metric uses when writing results.
       */
      airtime_metric_measured(const std::string& name = "Airtime-Measured");

      /**
       * airtime_metric_measured copy constuctor.
       *
       * \param other The other airtime_metric_measured to initialize from.
       */
      airtime_metric_measured(const airtime_metric_measured& other);

      /**
       * airtime_metric_measured assignment operator.
       *
       * \param other The other airtime_metric_measured to assign from.
       * \return A reference to this airtime_metric_measured.
       */
      airtime_metric_measured& operator=(const airtime_metric_measured& other);

      /**
       * airtime_metric_measured destructor.
       */
     virtual ~airtime_metric_measured();

      /**
       * Add a frame to the airtime_metric_measured and update the airtime_metric_measured statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this airtime_metric_measured
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A pointer to a new airtime_metric_measured instance.
       */
      virtual airtime_metric_measured *clone() const;

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
       * Name of this metric.
       */
      std::string name_;

      /**
       * Stashed value of this metric.
       */
      uint_least32_t airtime_;

      /**
       * Count of packets successfully delivered.
       */
      uint32_t packets_;

      /**
       * The computed value of the airtime metric.
       */
      double metric_;

      /**
       * Did we compute a valid metric?
       */
      bool valid_;

      /**
       * Additional debugging output we might want to see.
       */
      std::string debug_;

   };

}

#endif // METRICS_AIRTIME_METRIC_MEASURED_HPP
