/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_AIRTIME_METRIC_KERNEL_HPP
#define METRICS_AIRTIME_METRIC_KERNEL_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <map>

namespace metrics {

   /**
    * airtime_metric_kernel reports the average of the kernel metric
    * values seen during the measurement period and the instantaneous
    * value for the last packet. This requires that the kernel support
    * the NICTA vendor extension to radiotap.
    */
   class airtime_metric_kernel : public abstract_metric {
   public:

      /**
       * airtime_metric_kernel constructor.
       *
       * \param enc A non-null pointer to the encoding.
       * \param rts_cts_threshold Use RTS/CTS when rts_cts_threshold <= test frame size
       */
      explicit airtime_metric_kernel();

      /**
       * airtime_metric_kernel copy constuctor.
       *
       * \param other The other airtime_metric_kernel to initialize from.
       */
      airtime_metric_kernel(const airtime_metric_kernel& other);

      /**
       * airtime_metric_kernel assignment operator.
       *
       * \param other The other airtime_metric_kernel to assign from.
       * \return A reference to this airtime_metric_kernel.
       */
      airtime_metric_kernel& operator=(const airtime_metric_kernel& other);

      /**
       * airtime_metric_kernel destructor.
       */
     virtual ~airtime_metric_kernel();

      /**
       * Add a frame to the airtime_metric_kernel and update the airtime_metric_kernel statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this airtime_metric_kernel
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A pointer to a new airtime_metric_kernel instance.
       */
      virtual airtime_metric_kernel *clone() const;

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
       * The last packet's buffer_info.
       */
      net::buffer_info_sptr info_, last_info_;

      /**
       * Do we have a valid metric value?
       */
      bool valid_;

   };

}

#endif // METRICS_AIRTIME_METRIC_KERNEL_HPP
