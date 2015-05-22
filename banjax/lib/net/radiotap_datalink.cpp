/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2012 Steve Glass
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

#define __STDC_CONSTANT_MACROS

#include <net/buffer_body.hpp>
#include <net/radiotap.hpp>
#include <net/radiotap_datalink.hpp>
#include <util/byteswab.hpp>
#include <util/dump.hpp>
#include <util/exceptions.hpp>

#include <cstddef>
#include <pcap.h>
#include <vector>

using namespace std;
using namespace net;
using util::dump;
using util::le_to_cpu;
using util::raise;
using util::cpu_to_le;


radiotap_datalink::radiotap_datalink()
{
}

radiotap_datalink::~radiotap_datalink()
{
}

uint8_t*
radiotap_datalink::advance(uint8_t *& p, uint8_t field_sz)
{
   size_t n = field_sz - 1;
   uint8_t *x = reinterpret_cast<uint8_t*>((reinterpret_cast<size_t>(p) + n) & ~n);
   p = x + field_sz;
   return x;
}

size_t
radiotap_datalink::format(const buffer& b, size_t frame_sz, uint8_t *frame)
{
   CHECK_NOT_NULL(frame);

   uint8_t *p = frame + sizeof(radiotap_header);
   size_t p_sz = frame_sz;
   const_buffer_info_sptr info(b.info());
   radiotap_header *hdr = reinterpret_cast<radiotap_header*>(frame);
   uint32_t flags = 0;

   // compute radiotap header size
   if(info->has(TIMESTAMP1)) {
      flags |=  RADIOTAP_TSFT;
      advance(p, 8);
    }
   if(info->has(RX_FLAGS)) {
      flags |= RADIOTAP_FLAGS;
      advance(p, 1);
   }
   if(info->has(RATE_Kbs)) {
      flags |= RADIOTAP_RATE;
      advance(p, 1);
   }
   if(info->has(FREQ_MHz) && info->has(CHANNEL_FLAGS)) {
      flags |= RADIOTAP_CHANNEL;
      advance(p, 2);
      advance(p, 2);
   }
   if(info->has(SIGNAL_dBm)) {
      flags |= RADIOTAP_DBM_ANTSIGNAL;
      advance(p, 1);
   }
   if(info->has(TX_FLAGS)) {
      flags |= RADIOTAP_TXFLAGS;
      advance(p, 2);
   }
   if(info->has(RTS_RETRIES)) {
      flags |= RADIOTAP_RTS_RETRIES;
      advance(p, 1);
   }
   if(info->has(DATA_RETRIES)) {
      flags |= RADIOTAP_DATA_RETRIES;
      advance(p, 1);
   }

   // ensure everything will fit in output buffer
   uint16_t hdr_sz = p - frame;
   uint16_t reqd_sz = hdr_sz + b.data_size();
   if(frame_sz < reqd_sz) {
      ostringstream msg;
      msg << "output buffer too small for radiotap header and frame body" << endl;
      msg << reqd_sz << " < (" << hdr_sz << "+" << b.data_size() << ")" << endl;
      raise<length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   // write the header fields
   hdr->version_ = 0;
   cpu_to_le(hdr_sz, reinterpret_cast<uint8_t*>(&hdr->size_));
   cpu_to_le(flags, reinterpret_cast<uint8_t*>(&hdr->bitmaps_[0]));
   p = frame + sizeof(radiotap_header);
   if(info->has(TIMESTAMP1)) {
      uint64_t ts = info->timestamp1();
      cpu_to_le(ts, advance(p, 8));
   }
   if(info->has(RX_FLAGS)) {
      uint8_t f = 0;
      if(info->has(CHANNEL_FLAGS) && (info->channel_flags() & CHANNEL_PREAMBLE_SHORT))
         f |= RADIOTAP_FLAGS_SHORTPRE;
      if(info->rx_flags() & RX_FLAGS_BAD_FCS)
         f |= RADIOTAP_FLAGS_BAD_FCS;
      *(advance(p, 1)) = f;
   }
   if(info->has(RATE_Kbs)) {
      uint8_t rate_kbs = info->rate_Kbs() / 500;
      *(advance(p, 1)) = rate_kbs;
   }
   if(info->has(FREQ_MHz) && info->has(CHANNEL_FLAGS)) {
      uint16_t freq_MHz = info->freq_MHz();
      uint16_t chan_flags = 0;
      flags_t info_flags = info->channel_flags();
      if(info_flags & CHANNEL_CODING_DSSS)
         chan_flags |= RADIOTAP_CHAN_CCK;
      if(info_flags & CHANNEL_CODING_OFDM)
         chan_flags |= RADIOTAP_CHAN_OFDM;
      if(info_flags & CHANNEL_CODING_FHSS)
         chan_flags |= RADIOTAP_CHAN_GFSK;
      if(info_flags & CHANNEL_CODING_DYNAMIC)
         chan_flags |= RADIOTAP_CHAN_DYN;
      if(info_flags & CHANNEL_RATE_QUARTER)
         chan_flags |= RADIOTAP_CHAN_QUARTER_RATE;
      if(info_flags & CHANNEL_RATE_HALF)
         chan_flags |= RADIOTAP_CHAN_HALF_RATE;
      cpu_to_le(freq_MHz, advance(p, 2));
      cpu_to_le(chan_flags, advance(p, 2));
   }
   if(info->has(SIGNAL_dBm)) {      
      int8_t signal_dBm = info->signal_dBm();
      *(advance(p, 1)) = signal_dBm;
   }
   if(info->has(TX_FLAGS)) {
      uint16_t tx_flags = 0;
      if(info->tx_flags() & TX_FLAGS_FAIL)
         tx_flags |=  RADIOTAP_TXFLAGS_FAIL;
      cpu_to_le(tx_flags, advance(p,2));
   }
   if(info->has(RTS_RETRIES)) {
      uint8_t rts_retries = info->rts_retries();
      *(advance(p,1)) = rts_retries;
   }
   if(info->has(DATA_RETRIES)) {
      uint8_t data_retries = info->data_retries();
      *(advance(p,1)) = data_retries;
   }

   // now write the buffer content
   p = copy(b.data(), b.data() + b.data_size(), p);
   return p - frame;
}

const char*
radiotap_datalink::name() const
{
   return "IEEE 80211 (RADIOTAP)";
}

/**
 * Template helper function to exract a little-endian field from a
 * radiotap header taking care of alignment, byte-ordering and
 * buffer-overflow issues.
 *
 * \param ofs The offset of the field from the frame start.
 * \param field The field to extract.
 * \param hdr_sz The size of the radiotap_header.
 * \param frame_sz The size of the frame (including radiotap_header).
 * \param frame A pointer to the frame.
 * \throws length_error When reading would overflow the buffer.
 */
template<typename T> void extract(size_t& ofs, T& field, size_t hdr_sz, size_t frame_sz, const uint8_t *frame)
{
   const size_t field_sz = sizeof(field);
   const size_t align = field_sz - 1;
   ofs = (ofs + align) & ~align;
   if(!(ofs < hdr_sz)) {
      ostringstream msg;
      msg << "short read of argument from radiotap header at offset " << ofs << endl;
      msg << hex << dump(frame_sz, frame) << endl;
      raise<length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   le_to_cpu(frame + ofs, field);
   ofs += field_sz;
}

buffer_sptr
radiotap_datalink::parse(size_t frame_sz, const uint8_t *frame)
{
   CHECK_NOT_NULL(frame);

   const radiotap_header *hdr = reinterpret_cast<const radiotap_header*>(frame);
   if(0 != hdr->version_) {
      ostringstream msg;
      msg << "unsupported radiotap version (version=" << hex << showbase << setw(2) << setfill('0') << static_cast<uint16_t>(hdr->version_) << ")" << endl;
      msg << hex << dump(frame_sz, frame) << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   uint16_t hdr_sz = 0;
   le_to_cpu(reinterpret_cast<const uint8_t*>(&hdr->size_), hdr_sz);
   const size_t MIN_HDR_SZ = 8;
   if(!(MIN_HDR_SZ <= hdr_sz && hdr_sz <= frame_sz)) {
      ostringstream msg;
      msg << "partial read of radiotap header (expected " << MIN_HDR_SZ << " <= size <= " << frame_sz << ", actual size=" << hdr_sz << ")" << endl;
      msg << hex << dump(frame_sz, frame) << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   uint32_t bitmap = 0, ext_bitmap = 0;
   size_t ofs = offsetof(radiotap_header, bitmaps_);
   extract(ofs, bitmap, hdr_sz, frame_sz, frame);
   if(bitmap & RADIOTAP_EXT) {
      extract(ofs, ext_bitmap, hdr_sz, frame_sz, frame);
   }

   uint8_t oui[3];
   uint8_t sub_namespace = 0;
   uint16_t skip_sz = 0;
   flags_t rx_flags = 0;
   flags_t chan_flags = 0;
   buffer_info_sptr info(new buffer_info);
   for(uint32_t i = RADIOTAP_TSFT; i < RADIOTAP_EXT; i <<= 1) {
      int8_t junk_s8;
      uint8_t junk_u8;
      uint16_t junk_u16;
      uint32_t junk_u32;
      uint64_t junk_u64;
      uint32_t start_ts, end_ts;
      uint32_t bit = bitmap & i;
      switch(bit) {
      case RADIOTAP_TSFT:
         extract(ofs, junk_u64, hdr_sz, frame_sz, frame);
         info->timestamp1(junk_u64);
         break;
      case RADIOTAP_FLAGS:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         if(junk_u8 & RADIOTAP_FLAGS_FCS) {
            frame_sz -= sizeof(uint32_t); // remove FCS - banjax *never* provides FCS field
         }
         chan_flags |= (junk_u8 & RADIOTAP_FLAGS_SHORTPRE) ? CHANNEL_PREAMBLE_SHORT : CHANNEL_PREAMBLE_LONG;
         info->channel_flags(chan_flags);
         rx_flags |= (junk_u8 & RADIOTAP_FLAGS_BAD_FCS) ? RX_FLAGS_BAD_FCS : 0;
         info->rx_flags(rx_flags);
         break;
      case RADIOTAP_RATE:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         info->rate_Kbs(junk_u8 * 500);
         break;
      case RADIOTAP_CHANNEL:
         extract(ofs, junk_u16, hdr_sz, frame_sz, frame);
         info->freq_MHz(junk_u16);
         extract(ofs, junk_u16, hdr_sz, frame_sz, frame); 
         if(junk_u16 & (RADIOTAP_CHAN_TURBO | RADIOTAP_CHAN_STURBO)) {
            ostringstream msg;
            msg << "unsupported channel type in radiotap header (";
            msg << "channel flags =" << hex << showbase << setw(4) << junk_u16 << ")" << endl;
            msg << hex << dump(frame_sz, frame) << endl;
            raise<runtime_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
         }
         if(junk_u16 & RADIOTAP_CHAN_CCK)
            chan_flags |= CHANNEL_CODING_DSSS;
         if(junk_u16 & RADIOTAP_CHAN_OFDM)
            chan_flags |= CHANNEL_CODING_OFDM;
         if(junk_u16 & RADIOTAP_CHAN_GFSK)
            chan_flags |= CHANNEL_CODING_FHSS;
         if(junk_u16 & RADIOTAP_CHAN_DYN)
            chan_flags |= CHANNEL_CODING_DYNAMIC;
         if(junk_u16 & RADIOTAP_CHAN_QUARTER_RATE)
            chan_flags |= CHANNEL_RATE_QUARTER;
         else if(junk_u16 & RADIOTAP_CHAN_HALF_RATE)
            chan_flags |= CHANNEL_RATE_HALF;
         else
            chan_flags |= CHANNEL_RATE_FULL;
         info->channel_flags(chan_flags);
         break;
      case RADIOTAP_FHSS:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_DBM_ANTSIGNAL:
         extract(ofs, junk_s8, hdr_sz, frame_sz, frame);
         info->signal_dBm(junk_s8);
         break;
      case RADIOTAP_DBM_ANTNOISE:
         extract(ofs, junk_s8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_LOCK_QUALITY:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_TX_ATTENUATION:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_DB_TX_ATTENUATION:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_DBM_TX_POWER:
         extract(ofs, junk_s8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_ANTENNA:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_DB_ANTSIGNAL:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_DB_ANTNOISE:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         break;
      case RADIOTAP_RXFLAGS:
         extract(ofs, junk_u16, hdr_sz, frame_sz, frame);
         break;
         // from here onwards are "suggested fields"
      case RADIOTAP_TXFLAGS:
         extract(ofs, junk_u16, hdr_sz, frame_sz, frame);
         info->tx_flags((junk_u16 & RADIOTAP_TXFLAGS_FAIL) ? TX_FLAGS_FAIL : 0);
         break;
      case RADIOTAP_RTS_RETRIES:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         info->rts_retries(junk_u8);
         break;
      case RADIOTAP_DATA_RETRIES:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         info->data_retries(junk_u8);
         break;
      case RADIOTAP_VENDOR_NAMESPACE:
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         oui[0] = junk_u8;
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         oui[1] = junk_u8;
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         oui[2] = junk_u8;
         extract(ofs, junk_u8, hdr_sz, frame_sz, frame);
         sub_namespace = junk_u8;
         extract(ofs, junk_u16, hdr_sz, frame_sz, frame);
         skip_sz = junk_u16;
         break;
      default:
         break;
      }
   }

   if((bitmap & RADIOTAP_EXT) && (0x12 == oui[0] && 0x34 == oui[1] && 0x56 == oui[2])) {
      for(uint32_t i = RADIOTAP_TSFT; i < RADIOTAP_EXT; i <<= 1) {
         uint32_t bit = ext_bitmap & i;
         switch(bit) {
         case NICTA_PACKET_TIME:
         	{
               uint32_t queue_ts, head_ts, start_ts, end_ts;
               extract(ofs, queue_ts, hdr_sz, frame_sz, frame);
               extract(ofs, head_ts, hdr_sz, frame_sz, frame);
               extract(ofs, start_ts, hdr_sz, frame_sz, frame);
               extract(ofs, end_ts, hdr_sz, frame_sz, frame);
               if(start_ts && end_ts) {
                  info->timestamp1(start_ts);
                  info->timestamp2(end_ts);
               } else {
                  info->timestamp1(0);
                  info->timestamp2(0);
               }
            }
            break;
         case NICTA_AIRTIME_METRIC:
	         {
               uint32_t airtime = 0;
               extract(ofs, airtime, hdr_sz, frame_sz, frame);
               info->metric(airtime);
            }
            break;
         case NICTA_RATE_TUPLES:
         	{
               vector<uint32_t> rates;
               for(size_t i = 0; i < 4; ++i) {
                  uint8_t rate, flags, tries;
                  extract(ofs, rate, hdr_sz, frame_sz, frame);
                  extract(ofs, flags, hdr_sz, frame_sz, frame);
                  extract(ofs, tries, hdr_sz, frame_sz, frame);
                  for(uint16_t i = 0; i < tries; ++i) {
                     rates.push_back(rate * UINT32_C(500));
                  }
               }
               info->rates(rates);
            }
            break;
         default:
            break;
         }
      }
   }

   frame += hdr_sz;
   frame_sz -= hdr_sz;
   return buffer_sptr(new buffer_body(frame_sz, frame, info));
}

int
radiotap_datalink::type() const
{
   return DLT_IEEE802_11_RADIO;
}
