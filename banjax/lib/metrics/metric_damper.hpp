/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2012 NICTA
 *
 */

#ifndef METRICS_METRIC_DAMPER_HPP
#define METRICS_METRIC_DAMPER_HPP

#include <metrics/metric.hpp>

#include <deque>
#include <string>

namespace metrics {

   /**
    * metric_damper produces a moving average of the last n metrics.
    */
   class metric_damper : public metric {
   public:

      /**
       * metric_damper constructor.
       *
       * \param name The name of the damped metric.
       * \param metric Pointer to the metric to damp.
       * \param queue_sz The number of metrics in the window.
       */
      metric_damper(std::string name, metric_sptr metric, uint16_t queue_sz);

      /**
       * metric_damper copy constructor.
       *
       * \param other The other metric_damper to initialize from.
       */
      metric_damper(const metric_damper& other);

      /**
       * metric_damper assignment operator.
       *
       * \param other The other metric_damper to initialize from.
       * \return A reference to this metric_damper.
       */
      metric_damper& operator=(const metric_damper& other);

      /**
       * metric_damper destructor.
       */
      virtual ~metric_damper();

      /**
       * Return a pointer to a clone (a deep copy) of this
       * metric_damper instance. The clone is allocated on the heap
       * using new and the caller is responsible for ensuring it is
       * deleted.
       *
       * \return A poiner to a new metric_damper instance.
       */
      virtual metric_damper *clone() const;

      /**
       * Add a frame to the metric and update the metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Compute the metric. Subclasses must implement either this
       * method or the comput(uint32_t) version. Failure to do so will
       * result in a logic_error being thrown at runtime.
       *
       * \param mactime The 64 bit MAC time for the end of the time period.
       * \param delta_us The time (in microseconds) since we last computed the metric.
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
       * Name of the damped metric.
       */
      std::string name_;

      /**
       * The metric being damped.
       */
      metric_sptr metric_;

      /**
       * Maximum number of metrics in queue.
       */
      uint16_t queue_sz_;

      /**
       * A queue of the metrics.
       */
      std::deque<double> queue_;

      /**
       * Stashed value of the metric.
       */
      double value_;

   };

}

#endif // METRICS_METRIC_DAMPER_HPP
