/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/legacy_elc_metric.hpp>

#include <dot11/frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::legacy_elc_metric;


legacy_elc_metric::legacy_elc_metric(encoding_sptr enc, uint32_t rate_kbs, uint16_t mpdu_sz, uint16_t rts_cts_threshold) :
   abstract_metric(),
   enc_(enc),
   mpdu_sz_(mpdu_sz),
   rts_cts_threshold_(rts_cts_threshold),
   frames_attempted_(0),
   frames_attempted_octets_(0),
   frames_delivered_(0),
   frames_delivered_octets_(0),
   rates_kbs_sum_(0),
   rate_kbs_(closest_rate(rate_kbs)),
   classic_elc_(0.0),
   elc_(0.0)
{
}

legacy_elc_metric::legacy_elc_metric(const legacy_elc_metric& other) :
   abstract_metric(other),
   enc_(other.enc_),
   mpdu_sz_(other.mpdu_sz_),
   rts_cts_threshold_(other.rts_cts_threshold_),
   frames_attempted_(other.frames_attempted_),
   frames_attempted_octets_(other.frames_attempted_octets_),
   frames_delivered_(other.frames_delivered_),
   frames_delivered_octets_(other.frames_delivered_octets_),
   rates_kbs_sum_(other.rates_kbs_sum_),
   rate_kbs_(other.rate_kbs_),
   classic_elc_(other.classic_elc_),
   elc_(other.elc_)
{
}

legacy_elc_metric&
legacy_elc_metric::operator=(const legacy_elc_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      enc_ = other.enc_;
      mpdu_sz_ = other.mpdu_sz_;
      rts_cts_threshold_ = other.rts_cts_threshold_;
      frames_attempted_ = other.frames_attempted_;
      frames_attempted_octets_ = other.frames_attempted_octets_;
      frames_delivered_ = other.frames_delivered_;
      frames_delivered_octets_ = other.frames_delivered_octets_;
      rates_kbs_sum_ = other.rates_kbs_sum_;
      rate_kbs_ = other.rate_kbs_;
      classic_elc_ = other.classic_elc_;
      elc_ = other.elc_;
   }
   return *this;
}

legacy_elc_metric::~legacy_elc_metric()
{
}

void
legacy_elc_metric::add(buffer_sptr b)
{
   frame f(b);
   frame_control fc(f.fc());
   const uint32_t CRC_SZ = 4;
   buffer_info_sptr info(b->info());
   if(DATA_FRAME == fc.type() && info->has(TX_FLAGS)) {
      bool tx_success = !(info->tx_flags() & TX_FLAGS_FAIL);
      if(tx_success && info->channel_encoding() == enc_) {
       
         ++frames_delivered_;
         frames_delivered_octets_ += b->data_size() + CRC_SZ;
         rates_kbs_sum_ += info->rate_Kbs();
      }
      frames_attempted_octets_ += b->data_size() + CRC_SZ;
      frames_attempted_ += info->has(DATA_RETRIES) ? 1 + info->data_retries() : 1;
   }
}

legacy_elc_metric*
legacy_elc_metric::clone() const
{
   return new legacy_elc_metric(*this);
}

double
legacy_elc_metric::compute(uint32_t ignored_delta_us)
{

   const double ATTEMPTS = frames_attempted_;
   const double DELIVERED = frames_delivered_;
   const double AVG_RATE_kbs = rates_kbs_sum_ / DELIVERED;
   const double AVG_FRM_SZ = frames_delivered_octets_ / DELIVERED;

   /* ToDo: Computing the average rate (EMT) here is done the
    * straightforward way + then picking the nearest rate. There are
    * proposals to either use linear interpolation or to compute the
    * time differently. Check the pictures from the whiteboard!
    */

   const double EST_TX_TIME = successful_tx_time(closest_rate(AVG_RATE_kbs), AVG_FRM_SZ);
   const double EMT = AVG_FRM_SZ / EST_TX_TIME;
   const double FDR = DELIVERED / ATTEMPTS;
   elc_ = FDR * EMT;

   const uint16_t MPDU_SZ = mpdu_sz_;
   const rateset RATES(enc_->supported_rates());
   const uint16_t MAX_RATE = *(RATES.rbegin());
   const double TXTIME = successful_tx_time(rate_kbs_, MPDU_SZ);
   const double TMT = MPDU_SZ / TXTIME;
   classic_elc_ = FDR * TMT;

   return elc_;
}

void
legacy_elc_metric::reset()
{
   frames_attempted_ = 0;
   frames_attempted_octets_ = 0;
   frames_delivered_ = 0;
   frames_delivered_octets_ = 0;
   rates_kbs_sum_ = 0;
}

void
legacy_elc_metric::write(ostream& os) const
{
   os << "Legacy: " << elc_ << ", Classic: " << classic_elc_;
}

uint32_t
legacy_elc_metric::closest_rate(uint32_t r) const
{
   uint32_t rate = 0;
   uint32_t d = UINT32_MAX;
   rateset rates(enc_->supported_rates());
   for(rateset::const_iterator i(rates.begin()); i != rates.end(); ++i) {
      uint32_t t = llabs(static_cast<int64_t>(*i) - static_cast<int64_t>(r));
      if(t < d) {
         d = t;
         rate = *i;
      }      
   }
   return rate;
}

uint32_t 
legacy_elc_metric::successful_tx_time(uint32_t rate_kbs, uint16_t frame_sz) const
{
   const bool PREAMBLE = false; // ToDo: recover preamble from encoding

   const uint32_t T_CW = avg_contention_time(enc_, 0); // NB we don't consider increasing TXC!
   const uint32_t T_RTS_CTS = (rts_cts_threshold_ <= frame_sz) ? rts_cts_time(enc_, frame_sz, PREAMBLE) : 0;
   const uint32_t T_DATA = enc_->txtime(frame_sz, rate_kbs, false);
   const uint32_t ACK_SZ = 14;
   const uint32_t T_ACK = enc_->txtime(ACK_SZ, enc_->response_rate(rate_kbs), false);

   /* TODO: make QoS aware!
    */
   return /* AIFS[BE] */ 9 + enc_->DIFS() /* AIFS[BE] */ + T_CW + T_RTS_CTS + T_DATA + enc_->SIFS() + T_ACK;
}

// ToDo: interpolate the TXC!? Provide both results?
