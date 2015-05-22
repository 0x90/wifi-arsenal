/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#include <net/abstract_buffer.hpp>
#include <util/byteswab.hpp>

using namespace net;
using namespace util;

abstract_buffer::~abstract_buffer()
{
}

eui_48
abstract_buffer::read_mac(size_t i) const
{
   const size_t eui_48_sz = 6;
   return eui_48(eui_48_sz, read_octets(i, i + eui_48_sz));
}

uint8_t
abstract_buffer::read_u8(size_t i) const
{
   const uint8_t *x = read_octets(i, i + sizeof(uint8_t));
   return *x;
}

uint16_t
abstract_buffer::read_u16(size_t i) const
{
   uint16_t out;
   be_to_cpu(read_octets(i, i + sizeof(out)), out);
   return out;
}

uint16_t
abstract_buffer::read_u16_le(size_t i) const
{
   uint16_t out;
   le_to_cpu(read_octets(i, i + sizeof(out)), out);
   return out;
}

uint32_t
abstract_buffer::read_u32(size_t i) const
{
   uint32_t out;
   be_to_cpu(read_octets(i, i + sizeof(out)), out);
   return out;
}

uint32_t
abstract_buffer::read_u32_le(size_t i) const
{
   uint32_t out;
   le_to_cpu(read_octets(i, i + sizeof(out)), out);
   return out;
}

void
abstract_buffer::write_mac(size_t i, eui_48 mac)
{
   write_octets(i, i + mac.data_size(), mac.data());
}

void
abstract_buffer::write_u8(size_t i, uint8_t u)
{
   write_octets(i, i + sizeof(u), &u);
}

void
abstract_buffer::write_u16(size_t i, uint16_t u)
{
   const size_t n = sizeof(u);
   uint8_t x[n];
   cpu_to_be(u, x);
   write_octets(i, i + n, x);
}

void
abstract_buffer::write_u16_le(size_t i, uint16_t u)
{
   const size_t n = sizeof(u);
   uint8_t x[n];
   cpu_to_le(u, x);
   write_octets(i, i + n, x);
}

void
abstract_buffer::write_u32(size_t i, uint32_t u)
{
   const size_t n = sizeof(u);
   uint8_t x[n];
   cpu_to_be(u, x);
   write_octets(i, i + n, x);
}

void
abstract_buffer::write_u32_le(size_t i, uint32_t u)
{
   const size_t n = sizeof(u);
   uint8_t x[n];
   cpu_to_le(u, x);
   write_octets(i, i + n, x);
}

abstract_buffer::abstract_buffer()
{
}
