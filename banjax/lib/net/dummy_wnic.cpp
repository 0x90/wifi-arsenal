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

#include <net/dummy_wnic.hpp>

#include <pcap.h>

using namespace net;
using namespace std;

dummy_wnic::dummy_wnic(string dev_name, int dlt) :
   abstract_wnic(dev_name),
   dlt_(dlt)
{
}

dummy_wnic::~dummy_wnic()
{
}

int
dummy_wnic::datalink_type() const
{
   return dlt_;
}

void
dummy_wnic::filter(string filter_expr)
{
}
