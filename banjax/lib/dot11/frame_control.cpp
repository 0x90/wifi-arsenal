/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009 Steve Glass
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

#include <dot11/frame_control.hpp>

using namespace dot11;

frame_control::frame_control(const uint16_t fc) :
   fc_(fc)
{
}

const uint16_t type_bits = 0x000c;

frame_type
frame_control::type() const 
{
   return static_cast<frame_type>(fc_ & type_bits);
}

void 
frame_control::type(frame_type t)
{
   fc_ &= ~type_bits;
   fc_ |= static_cast<uint16_t>(t & type_bits);
}

const uint16_t subtype_bits = 0x00fc;

frame_subtype
frame_control::subtype() const 
{
   return static_cast<frame_subtype>(fc_ & subtype_bits);
}

void
frame_control::subtype(frame_subtype t)
{
   fc_ &= ~subtype_bits;
   fc_ |= static_cast<uint8_t>(t & subtype_bits);
}

const uint16_t to_ds_bit = 0x0100;

bool
frame_control::to_ds() const
{
   return static_cast<bool>(fc_ & to_ds_bit);
}

void frame_control::to_ds(bool b)
{
   fc_ &= ~to_ds_bit;
   fc_ |= (b ? to_ds_bit : 0);
}

const uint16_t from_ds_bit = 0x0200;

bool
frame_control::from_ds() const
{
   return static_cast<bool>(fc_ & from_ds_bit);
}

void
frame_control::from_ds(bool b)
{
   fc_ &= ~from_ds_bit;
   fc_ |= (b ? from_ds_bit : 0);
}

const uint16_t more_frag_bit = 0x0400;

bool
frame_control::more_frag() const
{
   return static_cast<bool>(fc_ & more_frag_bit);
}

void
frame_control::more_frag(bool b)
{
   fc_ &= ~more_frag_bit;
   fc_ |= (b ? more_frag_bit : 0);
}

const uint16_t retry_bit = 0x0800;

bool
frame_control::retry() const
{
   return static_cast<bool>(fc_ & retry_bit);
}

void
frame_control::retry(bool b)
{
   fc_ &= ~retry_bit;
   fc_ |= (b ? retry_bit : 0);
}

const uint16_t pwr_mgt_bit = 0x1000;

bool
frame_control::pwr_mgt() const
{
   return static_cast<bool>(fc_ & pwr_mgt_bit);
}

void
frame_control::pwr_mgt(bool b)
{
   fc_ &= ~pwr_mgt_bit;
   fc_ |= (b ? pwr_mgt_bit : 0);
}

const uint16_t more_data_bit = 0x2000;

bool
frame_control::more_data() const
{
   return static_cast<bool>(fc_ & more_data_bit);
}

void
frame_control::more_data(bool b)
{
   fc_ &= ~more_data_bit;
   fc_ |= (b ? more_data_bit : 0);
}

const uint16_t protected_frame_bit = 0x4000;

bool
frame_control::protected_frame() const
{
   return static_cast<bool>(fc_ & protected_frame_bit);
}

void
frame_control::protected_frame(bool b)
{
   fc_ &= ~protected_frame_bit;
   fc_ |= (b ? protected_frame_bit : 0);
}

const uint16_t order_bit = 0x8000;

bool
frame_control::order() const
{
   return static_cast<bool>(fc_ & order_bit);
}

void
frame_control::order(bool b)
{
   fc_ &= ~order_bit;
   fc_ |= (b ? order_bit : 0);
}

frame_control::operator uint16_t() const
{
   return fc_;
}
