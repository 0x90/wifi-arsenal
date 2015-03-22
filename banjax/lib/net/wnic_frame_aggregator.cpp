/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 * 
 */

#include <net/wnic_frame_aggregator.hpp>
#include <dot11/data_frame.hpp>
#include <dot11/frame.hpp>
#include <dot11/frame_type.hpp>
#include <dot11/sequence_control.hpp>
 
#include <iostream>
#include <iomanip>

using namespace net;
using namespace std;
using dot11::frame;
using dot11::CTRL_ACK;
using dot11::DATA_FRAME;

wnic_frame_aggregator::wnic_frame_aggregator(wnic_sptr w, const eui_48& ta) :
   wnic_wrapper(w),
   ta_(ta),
   state_(READING),
   seq_no_(0),
   first_(),
   last_(),
   txc_(0),
   frames_()
{
}

wnic_frame_aggregator::~wnic_frame_aggregator()
{
}

buffer_sptr
wnic_frame_aggregator::read()
{
   buffer_sptr b;
   for(;;) {
      switch(state_) {
      case READING:
         if(b = wnic_wrapper::read()) {
            frame f(b);
            if((f.fc().type() == DATA_FRAME) && (f.address2() == ta_) && f.address1().is_unicast()) {
               state_ = AGGREGATING;
               seq_no_ = f.sc().sequence_no();
               first_ = last_ = b;
               txc_ = 1;
            } else {
               return b;
            }
         } else {
            return b;
         }
         break;

      case AGGREGATING:
         if(b = wnic_wrapper::read()) {
            frame f(b);
            if((f.fc().type() == DATA_FRAME) && (f.address2() == ta_) && f.address1().is_unicast()) {
               if(f.sc().sequence_no() == seq_no_) {
                  last_ = b;
                  txc_++;
                  frames_.clear();
               } else {
                  // aggregate packet stats
                  buffer_sptr r(first_);
                  r->info()->timestamp2(last_->info()->timestamp2());
                  r->info()->data_retries(txc_ - 1);
                  r->info()->tx_flags(0);
                  // update aggregator state
                  state_ = DRAINING;
                  seq_no_ = f.sc().sequence_no();
                  first_ = last_ = b;
                  txc_ = 1;
                  return r;
               }
            } else if((f.fc().subtype() == CTRL_ACK) && (f.address1() == ta_)) {
               last_ = b;
               frames_.clear();
            } else {
               frames_.push_back(b);
            }
         } else {
            // aggregate packet stats
            buffer_sptr r(first_);
            r->info()->timestamp2(last_->info()->timestamp2());
            r->info()->data_retries(txc_ - 1);
            r->info()->tx_flags(0);
            // update aggregator state
            state_ = DRAINING;
            seq_no_ = 0;
            first_.reset();
            last_.reset();
            txc_ = 0;
            return r;
         }
         break;

      case DRAINING:
         if(0 < frames_.size()) {
            b = frames_.front();
            frames_.pop_front();
            return b;
         } else if(first_) {
            state_ = AGGREGATING;
         } else {
            state_ = READING;
         }
         break;
      }
   }
}
