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

#include <net/wnic_wrapper.hpp>

using namespace net;
using namespace std;

wnic_wrapper::~wnic_wrapper()
{
}

void
wnic_wrapper::filter(string filter_expr)
{
   wnic_->filter(filter_expr);
}

string
wnic_wrapper::name() const
{
   return wnic_->name();
}

buffer_sptr
wnic_wrapper::read()
{
   return wnic_->read();
}

void
wnic_wrapper::write(const buffer& b)
{
   wnic_->write(b);
}

wnic_wrapper::wnic_wrapper(wnic_sptr wnic) :
   wnic_(wnic)
{
}

int
wnic_wrapper::datalink_type() const
{
   return wnic_->datalink_type();
}
