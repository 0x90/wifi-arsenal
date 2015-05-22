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

#include <dot11/sequence_control.hpp>

using namespace dot11;

sequence_control::sequence_control(uint16_t sc) :
   sc_(sc)
{
}

const uint16_t fragment_bits = 0x000f;

uint8_t
sequence_control::fragment_no() const
{
   return(sc_ & fragment_bits);
}

void
sequence_control::fragment_no(uint8_t u)
{
   sc_ &= ~fragment_bits;
   sc_ |= (u & fragment_bits);
}

const uint16_t sequence_bits = 0xfff0;
const uint8_t sequence_shift = 4;

uint16_t
sequence_control::sequence_no() const
{
   return((sc_ & sequence_bits) >> sequence_shift);
}

void
sequence_control::sequence_no(uint16_t u)
{
   sc_ &= ~sequence_bits;
   sc_ |= ((u << sequence_shift) & sequence_bits);
}

sequence_control::operator uint16_t() const
{
   return sc_;
}
