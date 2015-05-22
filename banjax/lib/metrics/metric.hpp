/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_METRIC_HPP
#define METRICS_METRIC_HPP

#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>
#include <iosfwd>

namespace metrics {

   /**
    * Alias for shared_ptr<metric>.
    */
   typedef boost::shared_ptr<class metric> metric_sptr;

   /**
    * metric represents an estimation of some aspect of the network
    * traffic. Concrete implementations may provide metrics for
    * capacity/quality/utilization and so on.
    */
   class metric {
   public:

      /**
       * metric destructor.
       */
      virtual ~metric() = 0;
      
      /**
       * Add a frame to the metric and update the metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b) = 0;

      /**
       * Return a pointer to a clone (deep copy) of this metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new metric instance.
       */
      virtual metric *clone() const = 0;

      /**
       * Compute the metric.
       *
       * \param time The 64 bit MAC time for the end of the time period.
       * \param delta_us The time (in microseconds)  since the start of the time period.
       * \return The value of this metric as a double.
       */
      virtual double compute(uint64_t time, uint32_t delta_us) = 0;

      /**
       * Reset the internal state of the metric.
       */
      virtual void reset() = 0;

      /**
       * Write this object in human-readable form to ostream os.
       *
       * \param os A reference to the stream to write to.
       */
      virtual void write(std::ostream& os) const = 0;

   protected:

      /**
       * metric default constructor.
       */
      metric();

      /**
       * metric copy constructor.
       */
      metric(const metric& other);

      /**
       * metric copy constructor.
       */
      metric& operator=(const metric& other);

   };

   /**
    * operator to stream a metric to an ostream.
    *
    * \param os The stream to write to.
    * \param m The metric to be streamed.
    * \return A reference to the modified ostream.
    */
   inline std::ostream& operator<<(std::ostream& os, const metric& m)
   {
      m.write(os);
      return os;
   }

}

#endif // METRICS_METRIC_HPP
