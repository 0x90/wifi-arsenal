/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 *
 */

#ifndef METRICS_UTILIZATION_METRIC_HPP
#define METRICS_UTILIZATION_METRIC_HPP

#include <metrics/metric.hpp>

namespace metrics {

	/**
	 * utilization_metric computes the saturation. Unlike the
	 * saturation metric we assume we are running at a monitor node and
	 * so the appropriate IFS is added to each frame's time.
	 */
	class utilization_metric : public metric {
	public:

		/**
		 * utilization_metric constructor.
		 *
		 * \param name The name this metric uses when writing results.
		 */
		utilization_metric(const std::string& name = "utilization");

		/**
		 * utilization_metric copy constuctor.
		 *
		 * \param other The other utilization_metric to initialize from.
		 */
		utilization_metric(const utilization_metric& other);

		/**
		 * utilization_metric assignment operator.
		 *
		 * \param other The other utilization_metric to assign from.
		 * \return A reference to this utilization_metric.
		 */
		utilization_metric& operator=(const utilization_metric& other);

		/**
		 * utilization_metric destructor.
		 */
	  virtual ~utilization_metric();

		/**
		 * Add a frame to the utilization_metric and update the utilization_metric statistics.
		 *
		 * \param b A shared_pointer to the buffer containing the frame.
		 */
		virtual void add(net::buffer_sptr b);

		/**
		 * Return a pointer to a clone (deep copy) of this utilization_metric
		 * instance. The clone is allocated on the heap using new and
		 * the caller is responsible for ensuring it is deleted.
		 *
		 * \return A pointer to a new utilization_metric instance.
		 */
		virtual utilization_metric *clone() const;

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
       * Time (in microseconds) we can account for.
       */
      uint32_t time_;

		/**
		 * Value of this metric.
		 */
		double utilization_;

		/**
		 * Additional debugging output so we can "show our workings".
		 */
		std::string debug_;

	};

}

#endif // METRICS_UTILIZATION_METRIC_HPP
