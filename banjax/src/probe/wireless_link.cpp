/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright NICTA, 2011
 */

#define __STDC_LIMIT_MACROS ON
#define __STDC_CONSTANT_MACROS ON

#include <wireless_link.hpp>

#include <algorithm>

using namespace ETX;
using namespace std;

wireless_link::wireless_link(uint16_t window_sz) :
   last_seq_no_(0),
   rx_probe_count_(0),
   rx_probe_window_(0),
   RX_PROBE_WINDOW_MAX_(window_sz),
   rx_probes_(new uint16_t[RX_PROBE_WINDOW_MAX_]),
   rx_probes_loc_(0),
   tx_probe_count_(0),
   tx_probe_window_(0)
{
   fill(&rx_probes_[0], &rx_probes_[RX_PROBE_WINDOW_MAX_], 0);
}

wireless_link::~wireless_link()
{
   delete []rx_probes_;
}

void
wireless_link::advance_probe_window()
{
   rx_probes_[rx_probes_loc_] = rx_probe_count_;
   rx_probe_window_ = min(static_cast<uint16_t>(rx_probe_window_ + 1), RX_PROBE_WINDOW_MAX_);
   rx_probes_loc_ = (rx_probes_loc_ + 1) % RX_PROBE_WINDOW_MAX_;
   rx_probe_count_ = 0;
}

void
wireless_link::rx_probe(uint32_t seq_no)
{
   uint32_t missed = seq_no - last_seq_no_;
   const uint32_t PIVOT = UINT32_MAX / 2;
   if(missed < PIVOT) {
      ++rx_probe_count_;
      last_seq_no_ = seq_no;
   }
}

uint16_t
wireless_link::rx_probe_count() const
{
   uint16_t sum = 0;
   for(size_t i = 0; i < rx_probe_window_; ++i) {
      sum += rx_probes_[i];
   }
   return sum;
}

uint16_t
wireless_link::rx_probe_window() const
{
   return rx_probe_window_;
}

void
wireless_link::tx_delivery_ratio(uint16_t probe_count, uint16_t probe_window)
{
   tx_probe_count_ = probe_count;
   tx_probe_window_ = probe_window;
}

uint16_t
wireless_link::tx_probe_count() const
{
   return tx_probe_count_;
}

uint16_t
wireless_link::tx_probe_window() const
{
   return tx_probe_window_;
}
