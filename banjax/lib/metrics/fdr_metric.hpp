/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_FDR_METRIC_HPP
#define METRICS_FDR_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>

namespace metrics {

   /**
    * fdr_metric reports the FDR and the component values from which
    * it is computed.
    */
   class fdr_metric : public abstract_metric {
   public:

      /**
       * fdr_metric default constructor.
       *
       * \param enc The encoding used.
       */
      fdr_metric();

      /**
       * fdr_metric copy constuctor.
       *
       * \param other The other fdr_metric to initialize from.
       */
      fdr_metric(const fdr_metric& other);

      /**
       * fdr_metric assignment operator.
       *
       * \param other The other fdr_metric to assign from.
       * \return A reference to this fdr_metric.
       */
      fdr_metric& operator=(const fdr_metric& other);

      /**
       * fdr_metric destructor.
       */
     virtual ~fdr_metric();

      /**
       * Add a frame to the fdr_metric and update the fdr_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this fdr_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new fdr_metric instance.
       */
      virtual fdr_metric *clone() const;

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
       * The FDR.
       */
      double fdr_;

      /**
       * The total number of frames_delivered.
       */
      uint_least32_t frames_delivered_;

      /**
       * The stashed total number of frames_delivered.
       */
      uint_least32_t frames_delivered_stash_;

      /**
       * The total number of frame transmission attempts.
       */
      uint_least32_t frame_transmissions_;

      /**
       * The stashed total number of frame transmission attempts.
       */
      uint_least32_t frame_transmissions_stash_;

   };

}

#endif // METRICS_FDR_METRIC_HPP
