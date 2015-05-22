/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_ABSTRACT_METRIC_HPP
#define METRICS_ABSTRACT_METRIC_HPP

#include <metrics/metric.hpp>
#include <net/encoding.hpp>

namespace metrics {

   /**
    * abstract_metric is a default implementation of the metric
    * interface and defines some useful methods which are used by
    * several metric implementations.
    */
   class abstract_metric : public metric {
   public:

      /**
       * abstract_metric destructor.
       */
      virtual ~abstract_metric();

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
       * Compute the metric. This is called by the default
       * compute(uint64_t, uint32_t) and simply discards the (often
       * unused) mactime parameter.
       *
       * \param delta_us The time (in microseconds) since we last computed the metric.
       * \return The value of this metric as a double.
       */
      virtual double compute(uint32_t delta_us);

   protected:

      /**
       * abstract_metric default constructor.
       */
      abstract_metric();

      /**
       * abstract_metric copy constructor.
       */
      abstract_metric(const abstract_metric& other);

      /**
       * abstract_metric copy constructor.
       */
      abstract_metric& operator=(const abstract_metric& other);

      /**
       * Return the average contention window time for transmission
       * attempt txnum. We assume that the slot chosen is picked using
       * a random uniform distribution and so, on average, we wait for
       * half the contention window.
       *
       * \param enc The encoding used by the PHY layer.
       * \param txc The number of the (re)transmission attempt.
       * \return The time, in microseconds, that will be waited on average.
       */
      virtual double avg_contention_time(net::encoding_sptr enc, uint8_t txc) const;

      /**
       * Return the contention window size for transmission attempt
       * txc.
       *
       * \param enc The encoding used by the PHY layer.
       * \param txc The number of the (re)transmission attempt.
       * \return The maximum size, in slot times, of the contention window.
       */
      virtual uint16_t max_contention_slots(net::encoding_sptr enc, uint8_t txc) const;

      /**
       * Return the contention window time for transmission attempt
       * txnum. This value grows exponentially and is clamped to the
       * range allowed by the encoding.
       *
       * \param enc The encoding used by the PHY layer.
       * \param txc The number of the (re)transmission attempt.
       * \return The maximum time, in microseconds, used for the contention window.
       */
      virtual double max_contention_time(net::encoding_sptr enc, uint8_t txc) const;

      /**
       * Return the amount of time taken by the RTS/CTS exchange.
       *
       * \param enc A pointer to the frame encoding.
       * \param frame_sz The size of the data frame.
       * \param has_short_preamble true if short preambles are in use; otherwise false.
       * \return The time, in microseconds, used  by the RTS/CTS exchange.
       */
      virtual double rts_cts_time(net::encoding_sptr enc, uint32_t frame_sz, bool short_preamble) const;

      /**
       * Scan the standard rateset of the default encoding and return
       * the value which has the smallest difference to r.
       *
       * \param enc A non-NULL encoding_sptr.
       * \param r The rate to find.
       * \return The value in rates which is closest to r.
       */
      uint32_t closest_rate(net::encoding_sptr enc, uint32_t r) const;

   };

}

#endif // METRICS_ABSTRACT_METRIC_HPP
