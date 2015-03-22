/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/fdr_metric.hpp>

#include <dot11/frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::fdr_metric;

fdr_metric::fdr_metric() :
   abstract_metric(),
   fdr_(0.0),
   frames_delivered_(0),
   frames_delivered_stash_(0),
   frame_transmissions_(0),
   frame_transmissions_stash_(0)
{
}

fdr_metric::fdr_metric(const fdr_metric& other) :
   abstract_metric(other),
   fdr_(other.fdr_),
   frames_delivered_(other.frames_delivered_),
   frames_delivered_stash_(other.frames_delivered_stash_),
   frame_transmissions_(other.frame_transmissions_),
   frame_transmissions_stash_(other.frame_transmissions_stash_)
{
}

fdr_metric&
fdr_metric::operator=(const fdr_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      fdr_ = other.fdr_;
      frames_delivered_ = other.frames_delivered_;
      frames_delivered_stash_ = other.frames_delivered_stash_;
      frame_transmissions_ = other.frame_transmissions_;
      frame_transmissions_stash_ = other.frame_transmissions_stash_;
   }
   return *this;
}

fdr_metric::~fdr_metric()
{
}

void
fdr_metric::add(buffer_sptr b)
{
   frame f(b);
   frame_control fc(f.fc());
   buffer_info_sptr info(b->info());
   if(DATA_FRAME == fc.type() && info->has(TX_FLAGS)) {
      uint32_t txc = info->has(DATA_RETRIES) ? 1 + info->data_retries() : 1;
      bool tx_success = !(info->tx_flags() & TX_FLAGS_FAIL);
      if(tx_success) {
         ++frames_delivered_;
      }
      frame_transmissions_ += txc;
   }
}

fdr_metric*
fdr_metric::clone() const
{
   return new fdr_metric(*this);
}

double
fdr_metric::compute(uint32_t junk)
{
   fdr_ = static_cast<double>(frames_delivered_) / frame_transmissions_;
   frames_delivered_stash_ = frames_delivered_;
   frame_transmissions_stash_ = frame_transmissions_;
   return fdr_;
}

void
fdr_metric::reset()
{
   frames_delivered_ = 0;
   frame_transmissions_ = 0;
}

void
fdr_metric::write(ostream& os) const
{
   os << "Frames-Attempted: " << frame_transmissions_stash_ << ", ";
   os << "Frames-Delivered: " << frames_delivered_stash_ << ", ";
   os << "FDR: " << fdr_;
}
