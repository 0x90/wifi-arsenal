/* -*- Mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_TXC_METRIC_HPP
#define METRICS_TXC_METRIC_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <net/eui_48.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>
#include <string>

namespace metrics {

   /**
    * txc_metric reports the average transmit count.
    */
   class txc_metric : public abstract_metric {
   public:

      /**
       * txc_metric constructor. This computes the average TXC
       * for packets sent but, by default, excludes failed packets.
       *
       * \param name Label used to report metric.
       * \param use_all_packets Compute metric using good+bad packets.
       */
      txc_metric(const std::string name = "TXC");

      /**
       * txc_metric copy constuctor.
       *
       * \param other The other txc_metric to initialize from.
       */
      txc_metric(const txc_metric& other);

      /**
       * txc_metric assignment operator.
       *
       * \param other The other txc_metric to assign from.
       * \return A reference to this txc_metric.
       */
      txc_metric& operator=(const txc_metric& other);

      /**
       * txc_metric destructor.
       */
     virtual ~txc_metric();

      /**
       * Add a frame to the txc_metric and update the txc_metric statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this txc_metric
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A poiner to a new txc_metric instance.
       */
      virtual txc_metric *clone() const;

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
       * The label used for this metric.
       */
      std::string name_;

      /**
       * The average TXC value.
       */
      double txc_;

      /**
       * The total number of frames_delivered.
       */
      uint_least32_t frames_delivered_;

      /**
       * The total number of frame transmission attempts.
       */
      uint_least32_t frame_transmissions_;

      /**
       * The maximum TXC.
       */
      uint8_t max_txc_;

      /**
       * Somewhere so we can "show our workings".
       */
      std::string debug_;

   };

}

#endif // METRICS_TXC_METRIC_HPP
