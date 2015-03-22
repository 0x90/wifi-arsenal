/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_AIRTIME_METRIC_LINUX_HPP
#define METRICS_AIRTIME_METRIC_LINUX_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <map>

namespace metrics {

   /**
    * airtime_metric_linux is defined by 802.11s as its default
    * routing metric (see IEEE 802.11s-d8 s 11A.7).
    *
    * This version is based on the Linux kernel implementation found
    * in net/mac80211/mesh_hwmp.c.
    */
   class airtime_metric_linux : public abstract_metric {
   public:

      /**
       * airtime_metric_linux constructor.
       *
       * \param enc A non-null pointer to the encoding.
       * \param rts_cts_threshold Use RTS/CTS when rts_cts_threshold <= test frame size
       */
      explicit airtime_metric_linux(net::encoding_sptr enc);

      /**
       * airtime_metric_linux copy constuctor.
       *
       * \param other The other airtime_metric_linux to initialize from.
       */
      airtime_metric_linux(const airtime_metric_linux& other);

      /**
       * airtime_metric_linux assignment operator.
       *
       * \param other The other airtime_metric_linux to assign from.
       * \return A reference to this airtime_metric_linux.
       */
      airtime_metric_linux& operator=(const airtime_metric_linux& other);

      /**
       * airtime_metric_linux destructor.
       */
     virtual ~airtime_metric_linux();

      /**
       * Add a frame to the airtime_metric_linux and update the airtime_metric_linux statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this airtime_metric_linux
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A pointer to a new airtime_metric_linux instance.
       */
      virtual airtime_metric_linux *clone() const;

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
       * Pointer to the default channel encoding.
       */
      net::encoding_sptr enc_;

      /**
       * Moving average for frame loss (scaled to 100).
       */
      uint32_t fail_avg_;

      /**
       * The data rate we last sent at
       */
      uint32_t last_rate_Kbs_;

      /**
       * Stashed value of this metric.
       */
      double airtime_;

      /**
       * Count of packets successfully delivered.
       */
      uint32_t packets_;

      /**
       * Did we compute a valid metric?
       */
      bool valid_;

   };

}

#endif // METRICS_AIRTIME_METRIC_LINUX_HPP
