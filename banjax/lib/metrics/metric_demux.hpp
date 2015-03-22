/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_METRIC_DEMUX_HPP
#define METRICS_METRIC_DEMUX_HPP

#include <metrics/metric.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>
#include <map>

namespace metrics {

   /**
    * metric_demux gathers metrics on a per-link basis.
    */
   class metric_demux : public metric {
   public:

      /**
       * metric_demux constructor. Constructs a metric_demux which
       * will gather metrics of same type as proto for each of the
       * links on which we see traffic.
       *
       * \param proto A pointer to the metric prototype.
       */
      explicit metric_demux(metric_sptr proto);

      /**
       * metric_demux copy constructor.
       *
       * \param other A reference to the metric to copy construct from.
       */
      metric_demux(const metric_demux& other);

      /**
       * metric_demux assignment operator.
       *
       * \param other A reference to the metric to assign from.
       * \return A reference to this object.
       */
      metric_demux& operator=(const metric_demux& other);

      /**
       * metric_demux destructor.
       */
      virtual ~metric_demux();

      /**
       * Add a frame to the metric_demux and update the metric_demux statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (a deep copy) of this
       * metric_demux instance. The clone is allocated on the heap
       * using new and the caller is responsible for ensuring it is
       * deleted.
       *
       * \return A poiner to a new metric_demux instance.
       */
      virtual metric_demux *clone() const;

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
       * Return the link metric for the given address. If no metric is
       * present then a new instance is cloned from the prototype that
       * is passed to the metric_demux constructor.
       *
       * \param addr The address of the other end of this link.
       * \return A non-null pointer to a metric instance.
       */
      metrics::metric_sptr find(const net::eui_48& addr);

   private:

      /**
       * The prototype metric to use for all links.
       */
      metric_sptr proto_;

      /**
       * Alias for map<eui_48, link_metric_sptr>.
       */
      typedef std::map<net::eui_48, metrics::metric_sptr> linkmap;

      /**
       * Metrics on a per-link basis.
       */
      linkmap links_;

   };

}

#endif // METRICS_METRIC_DEMUX_HPP
