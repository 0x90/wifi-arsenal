/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#ifndef METRICS_AIRTIME_METRIC_NS3_HPP
#define METRICS_AIRTIME_METRIC_NS3_HPP

#include <metrics/abstract_metric.hpp>
#include <net/encoding.hpp>
#include <map>

namespace metrics {

   /**
    * airtime_metric_ns3 is defined by 802.11s as its default routing
    * metric (see IEEE 802.11s-d8 s 11A.7).
    *
    * This version is based on the metric found in the NS-3 network
    * simulator implementation of 802.11.
    */
   class airtime_metric_ns3 : public abstract_metric {
   public:

      /**
       * airtime_metric_ns3 constructor.
       *
       * \param enc A non-null pointer to the encoding.
       * \param rts_cts_threshold Use RTS/CTS when rts_cts_threshold <= test frame size
       */
      airtime_metric_ns3(net::encoding_sptr enc, uint16_t rts_cts_threshold);

      /**
       * airtime_metric_ns3 copy constuctor.
       *
       * \param other The other airtime_metric_ns3 to initialize from.
       */
      airtime_metric_ns3(const airtime_metric_ns3& other);

      /**
       * airtime_metric_ns3 assignment operator.
       *
       * \param other The other airtime_metric_ns3 to assign from.
       * \return A reference to this airtime_metric_ns3.
       */
      airtime_metric_ns3& operator=(const airtime_metric_ns3& other);

      /**
       * airtime_metric_ns3 destructor.
       */
     virtual ~airtime_metric_ns3();

      /**
       * Add a frame to the airtime_metric_ns3 and update the airtime_metric_ns3 statistics.
       *
       * \param b A shared_pointer to the buffer containing the frame.
       */
      virtual void add(net::buffer_sptr b);

      /**
       * Return a pointer to a clone (deep copy) of this airtime_metric_ns3
       * instance. The clone is allocated on the heap using new and
       * the caller is responsible for ensuring it is deleted.
       *
       * \return A pointer to a new airtime_metric_ns3 instance.
       */
      virtual airtime_metric_ns3 *clone() const;

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
       * The RTS/CTS threshold.
       */
      uint16_t rts_cts_threshold_;

      /**
       * Sum of TX rates.
       */
      uint_least32_t last_rate_Kbs_;

      /**
       * The time across which we compute the fail average.
       */
      uint64_t memory_time_;

      /**
       * Time of last update.
       */
      uint64_t last_update_;
      
      /**
       * Failure averaging mechanism.
       */
      double fail_avg_;

      /**
       * Stashed value of this metric.
       */
      double airtime_;

      /**
       * Count of successfully delivered packets.
       */
      uint32_t packets_;

      /**
       * Did we compute a valid metric?
       */
      bool valid_;
   };

}

#endif // METRICS_AIRTIME_METRIC_NS3_HPP
