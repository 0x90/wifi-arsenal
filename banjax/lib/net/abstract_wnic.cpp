/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2011 Steve Glass
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

#include <net/buffer.hpp>
#include <net/abstract_wnic.hpp>

using namespace net;
using namespace std;

abstract_wnic::~abstract_wnic()
{
}

string
abstract_wnic::name() const
{
   return name_;
}

buffer_sptr
abstract_wnic::read()
{
   buffer_sptr null;
   return null;
}

void
abstract_wnic::write(const buffer& b)
{
}

abstract_wnic::abstract_wnic(const string& name) :
   name_(name)
{
}
