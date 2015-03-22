/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 *
 */

#ifndef METRICS_SATURATION_METRIC_HPP
#define METRICS_SATURATION_METRIC_HPP

#include <metrics/metric.hpp>

namespace metrics {

	/**
	 * saturation_metric computes the saturation. Unlike the
	 * utilization metric we assume we are a sender node and assume
	 * that the times of outgoing packets includes the AIFS and
	 * contention and acknowledgment.
	 */
	class saturation_metric : public metric {
	public:

		/**
		 * saturation_metric constructor.
		 *
		 * \param name The name this metric uses when writing results.
		 */
		saturation_metric(const std::string& name = "saturation");

		/**
		 * saturation_metric copy constuctor.
		 *
		 * \param other The other saturation_metric to initialize from.
		 */
		saturation_metric(const saturation_metric& other);

		/**
		 * saturation_metric assignment operator.
		 *
		 * \param other The other saturation_metric to assign from.
		 * \return A reference to this saturation_metric.
		 */
		saturation_metric& operator=(const saturation_metric& other);

		/**
		 * saturation_metric destructor.
		 */
	  virtual ~saturation_metric();

		/**
		 * Add a frame to the saturation_metric and update the saturation_metric statistics.
		 *
		 * \param b A shared_pointer to the buffer containing the frame.
		 */
		virtual void add(net::buffer_sptr b);

		/**
		 * Return a pointer to a clone (deep copy) of this saturation_metric
		 * instance. The clone is allocated on the heap using new and
		 * the caller is responsible for ensuring it is deleted.
		 *
		 * \return A pointer to a new saturation_metric instance.
		 */
		virtual saturation_metric *clone() const;

      /**
       * Compute the metric.
       *
       * \param time The 64 bit MAC time for the end of the time period.
       * \param delta_us The time (in microseconds)  since the start of the time period.
       * \return The value of this metric as a double.
       */
      virtual double compute(uint64_t time, uint32_t delta_us);

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
       * Time (in microseconds) spent actually sending packets.
       */
      uint32_t time_;

		/**
		 * Value of this metric.
		 */
		double saturation_;

		/**
		 * Additional debugging output so we can "show our workings".
		 */
		std::string debug_;

	};

}

#endif // METRICS_SATURATION_METRIC_HPP
