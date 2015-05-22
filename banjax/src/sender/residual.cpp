/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS

#include <residual.hpp>
#include <dot11/data_frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::residual;

residual::residual(metric_sptr m, string name) :
   abstract_metric(),
   m_(m),
   name_(name),
   busy_time_(0),
   residual_(0.0)
{
}

residual::residual(const residual& other) :
   abstract_metric(other),
   m_(other.m_),
   name_(other.name_),
   busy_time_(other.busy_time_),
   residual_(other.residual_)
{
}

residual&
residual::operator=(const residual& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      m_ = other.m_;
      name_ = other.name_;
      busy_time_ = other.busy_time_;
      residual_ = other.residual_;
   }
   return *this;
}

residual::~residual()
{
}

void
residual::add(buffer_sptr b)
{
   m_->add(b);

   frame f(b);
   frame_control fc(f.fc());
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());

   const uint16_t RATE_Kbs = info->rate_Kbs();
   const size_t CRC_SZ = 4;
   const size_t FRAME_SZ = b->data_size() + CRC_SZ;

   if(info->has(TX_FLAGS)) {
      // ToDo: pass txc to airtime, use MRR rate info
      uint16_t txc = 1 + (info->has(DATA_RETRIES) ? info->data_retries() : 0);
      busy_time_ += txc * airtime(enc, RATE_Kbs, fc.type(), FRAME_SZ);
   } else {
      busy_time_ += airtime(enc, RATE_Kbs, fc.type(), FRAME_SZ);
   }
}

uint32_t
residual::airtime(encoding_sptr enc, uint16_t rate_Kbs, frame_type ft, uint32_t frame_sz) const
{
   uint32_t t;
   const bool PREAMBLE = false; // ToDo: get from encoding
   if(CTRL_FRAME == ft) {
      t = enc->SIFS() + enc->txtime(frame_sz, rate_Kbs, PREAMBLE);
   } else {
      t = enc->DIFS() + avg_contention_time(enc, 0) + enc->txtime(frame_sz, rate_Kbs, PREAMBLE);
   }
   return t;
}

residual*
residual::clone() const
{
   return new residual(*this);
}

double
residual::compute(uint64_t mactime, uint32_t delta_us)
{
   double idle_fraction = static_cast<double>(delta_us - busy_time_) / delta_us;
   residual_ = m_->compute(mactime, delta_us) * idle_fraction;
   return residual_;
}

void
residual::reset()
{
   m_->reset();
   busy_time_ = 0;
}

void
residual::write(ostream& os) const
{
   os << name_ << ": " << residual_;
}
