/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright NICTA, 2011
 */

#define __STDC_LIMIT_MACROS ON

#include <wireless_link_monitor.hpp>
#include <timespec.hpp>
#include <util/exceptions.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <boost/bind.hpp>
#include <boost/function/function0.hpp>
#include <boost/thread/thread.hpp>
#include <cstdlib>
#include <errno.h>
#include <iomanip>
#include <iostream>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

using namespace ETX;
using namespace std;
using namespace util;
using boost::function0;
using boost::mutex;
using boost::thread_group;


wireless_link_monitor::wireless_link_monitor(const string& bind_str, uint16_t port_no, uint16_t probe_sz, uint16_t window_sz, uint16_t delay_s, bool verbose) :
   bind_str_(bind_str),
   port_no_(port_no),
   probe_sz_(probe_sz),
   window_sz_(window_sz),
   delay_s_(delay_s),
   verbose_(verbose),
   addr_(INADDR_BROADCAST),
   quit_(false),
   seq_no_(0)
{
}

wireless_link_monitor::~wireless_link_monitor()
{
}

void
wireless_link_monitor::run(uint32_t dur_s)
{
   verbose_msg("starting run...");

   quit(false);

   // start the reader+writer
   boost::thread_group threads;
   threads.create_thread(function0<void>(boost::bind(&wireless_link_monitor::reader, this)));
   threads.create_thread(function0<void>(boost::bind(&wireless_link_monitor::writer, this)));

   // sleep
   timespec sleep, junk;
   sleep.tv_sec = dur_s;
   sleep.tv_nsec = 0; 
   clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep, &junk);

   // exit
   quit(true);
   threads.join_all();

   verbose_msg("exiting run");
}

uint32_t
wireless_link_monitor::addr() const
{
   mutex::scoped_lock lock(mutex_);
   return addr_;
}

void
wireless_link_monitor::addr(uint32_t a)
{
   mutex::scoped_lock lock(mutex_);
   addr_ = a;
}

bool
wireless_link_monitor::quit() const
{
   mutex::scoped_lock lock(mutex_);
   return quit_;
}

void
wireless_link_monitor::quit(bool b)
{
   mutex::scoped_lock lock(mutex_);
   quit_ = b;
}

void
wireless_link_monitor::raise_error(const char *func, const char* file, int line, int err, const char *what) const
{
   ostringstream msg;
   msg << what << ": " << strerror(errno) << " (" << errno << ")" << endl;
   raise<runtime_error>(func, file, line, msg.str());
}

void
wireless_link_monitor::read_probe(uint32_t neighbour_addr, const uint8_t *buf, size_t buf_sz)
{
   CHECK_NOT_NULL(buf);
   CHECK_MIN_SIZE(buf_sz, sizeof(probe));

   mutex::scoped_lock lock(mutex_);
   if(addr_ != neighbour_addr) {
      const probe *p = reinterpret_cast<const probe*>(buf);
      // update reverse delivery info
      wireless_link_sptr l;
      linkmap::iterator i(wireless_links_.find(neighbour_addr));
      if(wireless_links_.end() == i) {
         l = wireless_link_sptr(new wireless_link(window_sz_));
         wireless_links_[neighbour_addr] = l;
      } else {
         l = i->second;
      }
      l->rx_probe(ntohl(p->seq_no));
      // use probe to update tx delivery info
      uint16_t NOF_INFOS = ntohs(p->nof_infos);
      for(uint16_t i = 0; i < NOF_INFOS; ++i) {
         const probe::info *info = &p->wireless_links[i];
         const uint8_t *next = reinterpret_cast<const uint8_t*>(&p->wireless_links[i+1]);
         if(buf + buf_sz < next)
            break;
         // locate wireless_link and update metric
         uint32_t info_addr = ntohl(info->addr);
         if(addr_ == info_addr) {
            l->tx_delivery_ratio(ntohs(info->rx_probe_count), ntohs(info->rx_probe_window));
         }
      }
   }
}

void
wireless_link_monitor::reader()
{
   verbose_msg("starting reader...");

   try {

      // create socket
      int s = socket(AF_INET, SOCK_DGRAM, 0);
      if(-1 == s) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "socket(AF_INET, SOCK_DGRAM, 0)");
      }
 
		// enable  address re-use
      int ON = 1;
      if(-1 == setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON))) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON))");
      }

      // bind INADDR_ANY so we can receive packets addressed to INADDR_BROADCAST
      struct sockaddr_in src;
      memset(&src, sizeof(src), 0);
      src.sin_family = AF_INET;
      src.sin_port = htons(port_no_);
      src.sin_addr.s_addr = htonl(INADDR_ANY);
      if(-1 == bind(s, reinterpret_cast<const sockaddr*>(&src), sizeof(src))) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "bind(s, &dst, sizeof(dst))");
      }

      // mainloop
      while(!quit()) {
         struct sockaddr_in src;
         socklen_t src_sz = sizeof(src);
         uint8_t probe[/*802.11*/2036 - /*MAC*/26 - /*LLC*/8 - /*IP*/20 - /*UDP*/8 - /*FCS*/4];
         ssize_t probe_sz = recvfrom(s, probe, probe_sz, 0, reinterpret_cast<struct sockaddr*>(&src), &src_sz);
         if(-1 == probe_sz) {
            raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "recvfrom(s, probe, probe_sz, 0, &src, sizeof(src))");
         } else if(0 == probe_sz) {
            // zero-sized packet caused by writer thread
         } else {
            read_probe(src.sin_addr.s_addr, probe, probe_sz);
         }
      }
      close(s);

   } catch(const exception& x) {
      cerr << x.what() << endl;
      quit(true);
   } catch(...) {
      cerr << "unhandled exception" << endl;
      quit(true);
   }

   verbose_msg("exiting reader");
}

size_t
wireless_link_monitor::write_probe(uint8_t *buf, size_t buf_sz)
{
   uint16_t n = 0;
   uint8_t *next = buf;
   memset(buf, 0, buf_sz);
   probe *p = reinterpret_cast<probe*>(buf);

   mutex::scoped_lock lock(mutex_);
   p->seq_no = htonl(seq_no_++);
   p->packet_sz = htons(buf_sz);
   p->nof_infos = htons(wireless_links_.size());
   for(linkmap::iterator i(wireless_links_.begin()); i != wireless_links_.end(); ++i) {
      probe::info *info = &p->wireless_links[n++];
      next = reinterpret_cast<uint8_t*>(&p->wireless_links[n]);
      if(buf + buf_sz < next)
         break;
      wireless_link_sptr l = (*i).second;
      l->advance_probe_window();
      info->addr = htonl((*i).first);
      info->rx_probe_count = htons(l->rx_probe_count());
      info->rx_probe_window = htons(l->rx_probe_window());
   }
   return next - buf;
}

void
wireless_link_monitor::writer()
{
   verbose_msg("starting writer...");

   try {

      // create socket
      int s = socket(AF_INET, SOCK_DGRAM, 0);
      if(-1 == s) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "socket(AF_INET, SOCK_DGRAM, 0)");
      }

      // enable broadcast
      int ON = 1;
      if(-1 == setsockopt(s, SOL_SOCKET, SO_BROADCAST, &ON, sizeof(ON))) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "setsockopt(s, SOL_SOCKET, SO_BROADCAST, NULL, 0)");
      }

		// enable address re-use
      ON = 1;
      if(-1 == setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON))) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON))");
      }

      // restrict probes to specified address
      struct sockaddr_in src;
      memset(&src, sizeof(src), 0);
      src.sin_family = AF_INET;
      src.sin_port = htons(port_no_);
      int err = inet_aton(bind_str_.c_str(), &src.sin_addr); 
      if(0 == err) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "inet_aton(bind_str.c_str(), &src.sin_addr)");
      }
      if(-1 == bind(s, reinterpret_cast<const sockaddr*>(&src), sizeof(src))) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "bind(s, &dst, sizeof(dst))");
      }
      addr(src.sin_addr.s_addr);

      // setup timers
      timespec start, delta, jitter, tick, junk;
      if(-1 == clock_gettime(CLOCK_REALTIME, &start)) {
         raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "clock_gettime(CLOCK_REALTIME, &start)");
      } 
      delta.tv_sec = delay_s_;
      delta.tv_nsec = 0;

      // address outgoing packets
      struct sockaddr_in dst;
      memset(&dst, sizeof(dst), 0);
      dst.sin_family = AF_INET;
      dst.sin_port = htons(port_no_);
      dst.sin_addr.s_addr = INADDR_BROADCAST;

      // main loop
      for(uint32_t i = 0; i < UINT32_MAX && !quit(); ++i) {
         uint8_t probe[probe_sz_];
         size_t probe_sz = write_probe(probe, probe_sz_);
         if(-1 == sendto(s, probe, probe_sz_, 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst))) {
            raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "sendto(s, probe, probe_sz_, 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst))");
         }
         tick = start + (delta * i) /* + jitter */;
         int err = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &tick, &junk);
         if(-1 == err) {
            raise_error(__PRETTY_FUNCTION__, __FILE__, __LINE__, errno, "clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &tick, &junk)");
         }
      }
      close(s);

   } catch(const exception& x) {
      cerr << x.what() << endl;
      quit(true);
   } catch(...) {
      cerr << "unhandled exception" << endl;
      quit(true);
   }

   verbose_msg("exiting writer");
}

void
wireless_link_monitor::verbose_msg(const string& msg)
{
   if(verbose_)
      cout << msg << endl;
}
