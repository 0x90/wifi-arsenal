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

#ifndef DOT11_FRAME_SUBTYPE_HPP
#define DOT11_FRAME_SUBTYPE_HPP

namespace dot11 {
   enum frame_subtype {

      MGMT_ASSOC_REQ           = 0x00,
      MGMT_ASSOC_RESP          = 0x10,
      MGMT_REASSOC_REQ         = 0x20,
      MGMT_REASSOC_RESP        = 0x30,
      MGMT_PROBE_REQ           = 0x40,
      MGMT_PROBE_RESP          = 0x50,
      MGMT_BEACON              = 0x80,
      MGMT_ATIM                = 0x90,
      MGMT_DISASSOC            = 0xa0,
      MGMT_AUTHENTICATE        = 0xb0,
      MGMT_DEAUTHENTICATE      = 0xc0,
      MGMT_ACTION              = 0xd0,
      CTRL_PS_POLL             = 0xa4,
      CTRL_RTS                 = 0xb4,
      CTRL_CTS                 = 0xc4,
      CTRL_ACK                 = 0xd4,
      CTRL_CF_END              = 0xe4,
      CTRL_CF_END_CF_ACK       = 0xf4,
      DATA                     = 0x08,
      DATA_CF_ACK              = 0x18,
      DATA_CF_POLL             = 0x28,
      DATA_CF_ACK_CF_POLL      = 0x38,
      DATA_NULL                = 0x48,
      DATA_NULL_CF_ACK         = 0x58,
      DATA_NULL_CF_POLL        = 0x68,
      DATA_CF_POLL_CF_ACK      = 0x78,
      DATA_QOS                 = 0x88,
      DATA_QOS_CF_ACK          = 0x98,
      DATA_QOS_CF_POLL         = 0xa8,
      DATA_QOS_CF_ACK_CF_POLL  = 0xb8,
      DATA_QOS_NULL            = 0xc8,
      DATA_QOS_NULL_CF_ACK     = 0xe8,
      DATA_QOS_NULL_CF_POLL    = 0xf8,
      DATA_QOS_CF_POLL_CF_ACK  = 0x78,

   };
}

#endif // DOT11_FRAME_SUBTYPE_HPP
