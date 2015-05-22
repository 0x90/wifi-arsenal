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

#ifndef DOT11_FRAME_TYPE_HPP
#define DOT11_FRAME_TYPE_HPP

namespace dot11 {
   enum frame_type {
      MGMT_FRAME = 0x00,
      CTRL_FRAME = 0x04,
      DATA_FRAME = 0x08,
   };
}

#endif // DOT11_FRAME_TYPE_HPP
