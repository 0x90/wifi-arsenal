/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 */

#include <net/channel.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <math.h>
#include <sstream>
#include <stdexcept>

using namespace net;
using namespace std;
using util::raise;

const channel::info channel::INFOS_[] = {
   {  1, 2412, "2.4GHz ISM"},
   {  2, 2417, "2.4GHz ISM"},
   {  3, 2422, "2.4GHz ISM"},
   {  4, 2427, "2.4GHz ISM"},
   {  5, 2432, "2.4GHz ISM"},
   {  6, 2437, "2.4GHz ISM"},
   {  7, 2442, "2.4GHz ISM"},
   {  8, 2447, "2.4GHz ISM"},
   {  9, 2452, "2.4GHz ISM"},
   { 10, 2457, "2.4GHz ISM"},
   { 11, 2462, "2.4GHz ISM"},
   { 12, 2467, "2.4GHz ISM"},
   { 13, 2472, "2.4GHz ISM"},
   { 14, 2484, "2.4GHz ISM"},
   { 34, 5170, "UNII Lower"},
   { 36, 5180, "UNII Lower"},
   { 38, 5190, "UNII Lower"},
   { 40, 5200, "UNII Lower"},
   { 42, 5210, "UNII Lower"},
   { 44, 5220, "UNII Lower"},
   { 46, 5230, "UNII Lower"},
   { 48, 5240, "UNII Lower"},
   { 52, 5260, "UNII Middle"},
   { 56, 5280, "UNII Middle"},
   { 60, 5300, "UNII Middle"},
   { 64, 5320, "UNII Middle"},
   {100, 5500, "UNII"},
   {104, 5520, "UNII"},
   {108, 5540, "UNII"},
   {112, 5560, "UNII"},
   {116, 5580, "UNII"},
   {120, 5600, "UNII"},
   {149, 5745, "UNII High"},
   {153, 5765, "UNII High"},
   {157, 5785, "UNII High"},
   {161, 5805, "UNII High"},
   {165, 5825, "UNII"}
};

channel::channel(uint16_t no)
{
   const size_t nof_infos = sizeof(INFOS_) / sizeof(&INFOS_[0]);
   for(const info *i = &INFOS_[0]; i != &INFOS_[nof_infos]; ++i) {
      if(i->no_ == no) {
         info_ = i;
         return;
      }
   }
   ostringstream msg;
   msg << "bad channel number (channel " << no << ")";
   raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
}

channel::channel(uint16_t freq_MHz, enum freq_unit ignored)
{
   CHECK_EQUAL(ignored, MHz);
   const size_t nof_infos = sizeof(INFOS_) / sizeof(&INFOS_[0]);
   for(const info *i = &INFOS_[0]; i != &INFOS_[nof_infos]; ++i) {
      if(i->freq_MHz_ == freq_MHz) {
         info_ = i;
         return;
      }
   }
   ostringstream msg;
   msg << "bad channel number (frequency " << freq_MHz << "MHz)";
   raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
}

channel::channel(const channel& other) :
   info_(other.info_)
{
}

channel& channel::operator=(const channel& other)
{
   if(this != &other) {
      info_ = other.info_;
   }
   return *this;
}

channel::~channel()
{
   info_ = NULL;
}

bool
channel::operator==(const channel& other) const
{
   return info_ == other.info_;
}

bool
channel::operator<(const channel& other) const
{
   return freq_MHz() < other.freq_MHz();
}

uint16_t
channel::freq_MHz() const
{
   return info_->freq_MHz_;
}

uint16_t
channel::number() const
{
   return info_->no_;
}

void
channel::write(ostream& os) const
{
   os << "channel " << info_->no_ << " (" << info_->freq_MHz_ << "MHz) " << info_->band_;
}

std::ostream&
net::operator<<(std::ostream& os, const channel& chan)
{
   chan.write(os);
   return os;
}
