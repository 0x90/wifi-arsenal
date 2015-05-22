/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright NICTA, 2011
 */

#ifndef ETX_WIRELESS_LINK_MONITOR_HPP
#define ETX_WIRELESS_LINK_MONITOR_HPP

#include <wireless_link.hpp>

#include <boost/noncopyable.hpp>
#include <boost/thread/mutex.hpp>

namespace ETX {

	/**
    * wireless_link_monitor is responsible for sending and monitoring ETX
    * link quality probes to/from our neighbours. This function sends
    * packet_sz probe packets at intervals of delay_ms.
    */
   class wireless_link_monitor : public boost::noncopyable {
   public:

      /**
       * Construct a new wireless link quality monitor with the
       * specified attributes. If a specific interface address is
       * given in bind_str then we bind to that and restrict probes to
       * just that interface; otherwise probes are sent on all
       * available interfaces.
       *
       * \param bind_str A string specifying the IP address to bind.
       * \param port_no The port number to use.
       * \param probe_sz The size of the probe packets.
       * \param window_sz The number of elements in the probe window.
       * \param delay_s The delay between subsequent probes (in seconds).
       * \param verbose true for verbose output; otherwise false.
       */
      wireless_link_monitor(const std::string& bind_str, uint16_t port_no, uint16_t probe_sz, uint16_t window_sz, uint16_t delay_s, bool verbose);

      /**
       * wireless_link_monitor destructor.
       */
      ~wireless_link_monitor();

      /**
       * Run the wireless_link_monitor for the specified time period.
       *
       * \param duration_s The time to run for in s.
       */
      void run(uint32_t duration_s);

   private:

      /**
       * Return the IP address of the writer interface.
       */
      uint32_t addr() const;

      /**
       * Store the IP address of the writer interface.
       */
      void addr(uint32_t a);

      /**
       * Tests whether the threads should terminate,
       *
       * \return A boolean indicating if the thread should quit.
       */
      bool quit() const;

      /**
       * Tell worker threads its time to quit. The strategy used is to
       * set a flag that the threads check each time around their
       * mainloop.
       *
       * \param b The new value for the quit attribute.
       */
      void quit(bool b);

      /**
       * Raise a runtime_error with the specified parameters.
       *
       * \param func The function (__PRETTY_FUNCTION__).
       * \param file The file (__FILE__).
       * \param line The line number (__LINE__).
       * \param err The errno value.
       * \param what Text to display.
       */
      void raise_error(const char *func, const char *file, int line, int err, const char *what) const;

      /**
       * Parse the received probe and update the link quality
       * information. We extract our own forward delivery ratio from
       * the probe payload and pass it to the wireless_link object.
       *
       * \param neighbour_addr Address of neighbour (in host order).
       * \param buf A (non-null) pointer to the probe packet. 
       * \param buf_sz The size of the probe packet.
       */
      void read_probe(uint32_t neighbour_addr, const uint8_t *buf, size_t buf_sz);

      /**
       * Reader thread, launched asynchronously by
       * <tt>run(uint32_t)</tt> to receive probes and recover the
       * reverse delivery ratio from each of our neighbours.
       */
      void reader();

      /**
       * Write a probe packet to the specified buffer.
       *
       * \param buf A (non-null) pointer to the probe packet. 
       * \param buf_sz The size of the probe packet.
       * \return The actual number of octets written to the buffer.
       */
      size_t write_probe(uint8_t *buf, size_t buf_sz);

      /**
       * Writer thread, launched asynchronously by
       * <tt>run(uint32_t)</tt> to send probes advertising our forward
       * delivery ratio to each of our neighbours.
       */
      void writer();

   private:

      /**
       * Write a message to cout when verbose messaging enabled.
       *
       * \param msg The text to write.
       */
      void verbose_msg(const std::string& msg);

   private:

      /**
       * The interface to bind to (for outgoing packets).
       */
      std::string bind_str_;

      /**
       * The port number to use.
       */
      uint16_t port_no_;

      /**
       * The (minimum) probe size.
       */
      size_t probe_sz_;

      /**
       * The size of the received probe window.
       */
      uint16_t window_sz_;
      
      /**
       * The interval between successive probes.
       */
      uint16_t delay_s_;

      /**
       * Flag to control verbose output.
       */
      bool verbose_;

      /**
       * Lock for shared structures.
       */
      mutable boost::mutex mutex_;

      /**
       * The address of the interface the writer is bound to.
       */
      volatile uint32_t addr_;

      /**
       * Should background threads quit yet?
       */
      volatile bool quit_;

      /**
       * Alias for map<uint32_t, wireless_link_sptr>.
       */
      typedef std::map<uint32_t, wireless_link_sptr> linkmap;

      /**
       * The sequence number of the next probe.
       */
      uint32_t seq_no_;

      /**
       * All the wireless_links we know about.
       */
      linkmap wireless_links_;

      /**
       * Physical representation of probe packet. All numeric
       * quantities are sent in network order.
       */
      struct __attribute__((__packed__)) probe
      {

         /**
          * Monotonically increasing seq_no.
          */
         uint32_t seq_no;

         /**
          * The total size of this probe packet in octets.
          */
         uint16_t packet_sz;

         /**
          * Count of the number of wireless_link_infos that follow.
          */
         uint16_t nof_infos;

         /**
          * info for each neighbour of sender.
          */
         struct __attribute__((__packed__)) info
         {
            /**
             * The address of the neighbour.
             */
            uint32_t addr;

            /**
             * The number of probes received during the probe window.
             */
            uint16_t rx_probe_count;

            /**
             * The number of probes in the window.
             */
            uint16_t rx_probe_window;

         } wireless_links[0];

      };

   };

}

#endif // ETX_WIRELESS_LINK_MONITOR_HPP
