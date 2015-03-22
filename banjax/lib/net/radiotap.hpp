/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2012 Steve Glass
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

#ifndef NET_RADIOTAP_HPP
#define NET_RADIOTAP_HPP

#include <stdint.h>  

namespace net {

   const uint32_t RADIOTAP_TSFT              = 0x0001;
   const uint32_t RADIOTAP_FLAGS             = 0x0002;
   const uint32_t RADIOTAP_RATE              = 0x0004;
   const uint32_t RADIOTAP_CHANNEL           = 0x0008;
   const uint32_t RADIOTAP_FHSS              = 0x0010;
   const uint32_t RADIOTAP_DBM_ANTSIGNAL     = 0x0020;
   const uint32_t RADIOTAP_DBM_ANTNOISE      = 0x0040;
   const uint32_t RADIOTAP_LOCK_QUALITY      = 0x0080;
   const uint32_t RADIOTAP_TX_ATTENUATION    = 0x0100;
   const uint32_t RADIOTAP_DB_TX_ATTENUATION = 0x0200;
   const uint32_t RADIOTAP_DBM_TX_POWER      = 0x0400;
   const uint32_t RADIOTAP_ANTENNA           = 0x0800;
   const uint32_t RADIOTAP_DB_ANTSIGNAL      = 0x1000;
   const uint32_t RADIOTAP_DB_ANTNOISE       = 0x2000;
   const uint32_t RADIOTAP_RXFLAGS           = 0x4000;
   const uint32_t RADIOTAP_TXFLAGS           = 0x8000;
   const uint32_t RADIOTAP_RTS_RETRIES       = 0x10000;
   const uint32_t RADIOTAP_DATA_RETRIES      = 0x20000;
   const uint32_t RADIOTAP_NAMESPACE         = 0x20000000;
   const uint32_t RADIOTAP_VENDOR_NAMESPACE  = 0x40000000;
   const uint32_t RADIOTAP_EXT               = 0x80000000;

   const uint8_t  RADIOTAP_FLAGS_CFP         = 0x01;
   const uint8_t  RADIOTAP_FLAGS_SHORTPRE    = 0x02;
   const uint8_t  RADIOTAP_FLAGS_WEP         = 0x04;
   const uint8_t  RADIOTAP_FLAGS_FRAG        = 0x08;
   const uint8_t  RADIOTAP_FLAGS_FCS         = 0x10;
   const uint8_t  RADIOTAP_FLAGS_PAD         = 0x20;
   const uint8_t  RADIOTAP_FLAGS_BAD_FCS     = 0x40;
   const uint8_t  RADIOTAP_FLAGS_SHORTGRD    = 0x80;

   const uint16_t RADIOTAP_CHAN_TURBO        = 0x0010;
   const uint16_t RADIOTAP_CHAN_CCK          = 0x0020;
   const uint16_t RADIOTAP_CHAN_OFDM         = 0x0040;
   const uint16_t RADIOTAP_CHAN_2GHZ         = 0x0080;
   const uint16_t RADIOTAP_CHAN_5GHZ         = 0x0100;
   const uint16_t RADIOTAP_CHAN_PASSIVE      = 0x0200;
   const uint16_t RADIOTAP_CHAN_DYN          = 0x0400;
   const uint16_t RADIOTAP_CHAN_GFSK         = 0x0800;
   const uint16_t RADIOTAP_CHAN_900MHZ       = 0x1000;
   const uint16_t RADIOTAP_CHAN_STURBO       = 0x2000;
   const uint16_t RADIOTAP_CHAN_HALF_RATE    = 0x4000;
   const uint16_t RADIOTAP_CHAN_QUARTER_RATE = 0x8000;

   const uint16_t RADIOTAP_TXFLAGS_FAIL      = 0x0001;
   const uint16_t RADIOTAP_TXFLAGS_CTS       = 0x0002;
   const uint16_t RADIOTAP_TXFLAGS_RTS_CTS   = 0x0004;
   const uint16_t RADIOTAP_TXFLAGS_NO_ACK    = 0x0008;

   const uint16_t RADIOTAP_RXFLAGS_BAD_FCS   = 0x0001;
   const uint16_t RADIOTAP_RXFLAGS_BAD_PLCP  = 0x0002;

   // NICTA vendor extensions
   const uint32_t NICTA_OUID                 = 0x123456;
   const uint32_t NICTA_PACKET_TIME          = 0x0001;
   const uint32_t NICTA_AIRTIME_METRIC       = 0x0002;
   const uint32_t NICTA_RATE_TUPLES          = 0x0004;

}

#endif // NET_RADIOTAP_HPP
