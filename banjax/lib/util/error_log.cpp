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

#include <util/error_log.hpp>

#include <iostream>
#include <iomanip>

using namespace std;
using namespace util;

error_log&
error_log::get()
{
   static error_log instance;
   return instance;
}

void
error_log::log_unhandled(const char *func, const char *file, int line)
{
   cerr << "unhandled exception! " << endl;
   cerr << "caught in " << func << ", at line " << line << " of " << file << endl;
}

void
error_log::log_unhandled(const char *func, const char *file, int line, const exception& x)
{
   cerr << "unhandled exception! " << endl;
   cerr << x.what() << endl;
   cerr << "caught in " << func << ", at line " << line << " of " << file << endl;
}
