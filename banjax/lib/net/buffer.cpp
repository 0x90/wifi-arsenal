/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009,2011 Steve Glass
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
#include <util/dump.hpp>

#include <iostream>
#include <iomanip>

using namespace net;
using namespace std;
using util::dump;

buffer::~buffer()
{
}

buffer::buffer()
{
}

void
buffer::write(ostream& os) const
{
   os << dump(data_size(), data()) << endl;
}

std::ostream&
net::operator<<(std::ostream& os, const buffer& buf)
{
   buf.write(os);
   return os;
}
