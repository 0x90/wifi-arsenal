/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 */

#ifdef __linux__

#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include <net/buffer.hpp>
#include <net/linux_wnic.hpp>
#include <util/exceptions.hpp>
#include <util/syscall_error.hpp>

#include <arpa/inet.h>
#include <cstring>
#include <linux/filter.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>

using namespace net;
using namespace std;
using boost::shared_ptr;
using util::raise;
using util::syscall_error;

linux_wnic::linux_wnic(string name) :
   abstract_wnic(name),
   dl_()
{
   socket_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   if(-1 == socket_) {
      ostringstream msg;
      msg << "socket(PF_PACKET, SOCK_RAW, ETH_P_ALL): " << strerror(errno);
      raise<syscall_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   struct ifreq ifr;
   dev_ioctl(SIOCGIFINDEX, ifr);
   struct sockaddr_ll addr;
   bzero(&addr, sizeof(addr));
   addr.sll_family   = AF_PACKET;
   addr.sll_protocol = htons(ETH_P_ALL);
   addr.sll_ifindex  = ifr.ifr_ifindex;
   if(-1 == bind(socket_, (struct sockaddr*) &addr, sizeof(addr))) {
      ostringstream msg;
      msg << "bind(s, (struct sockaddr*) &addr, sizeof(addr)): ";
      msg << strerror(errno) << endl;
      raise<syscall_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   struct ifreq wrq;
   bzero(&wrq, sizeof(wrq));
   dev_ioctl(SIOCGIFHWADDR, wrq);
   dl_ = datalink::get(datalink_type(wrq.ifr_hwaddr.sa_family));
}

linux_wnic::~linux_wnic()
{
   close(socket_);
}

int
linux_wnic::datalink_type() const
{
   return dl_->type();
}

void
linux_wnic::filter(string filter_expr)
{
   const int SNAPLEN = 8192;
   pcap_t *pcap = pcap_open_dead(datalink_type(), SNAPLEN);

   struct bpf_program bpf;
   if(-1 == pcap_compile(pcap, &bpf, filter_expr.c_str(), 1, 0 /* PCAP_NETMASK_UNKNOWN */)) {
      ostringstream msg;
      msg << "pcap_compile(pcap_, &bpf, \"";
      msg << filter_expr;
      msg << "\", 1, PCAP_NETMASK_UNKNOWN): ";
      msg << pcap_geterr(pcap) << endl;
      pcap_close(pcap);
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }

   // DANGER: bpf_program and sock_fprog are defined to be the same
	// but this is purely a structural equivalence that may break in
	// future.
   struct sock_fprog *filt_prog = reinterpret_cast<sock_fprog*>(&bpf);
   if(-1 == setsockopt(socket_, SOL_SOCKET, SO_ATTACH_FILTER, filt_prog, sizeof(sock_fprog))) {
      ostringstream msg;
      msg << "setsockopt(socket_, SOL_SOCKET, SO_ATTACH_FILTER, filt_prog, sizeof(sock_fprog)):";
      msg << strerror(errno) << endl;
      pcap_freecode(&bpf);
      pcap_close(pcap);
      raise<syscall_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   pcap_freecode(&bpf);
   pcap_close(pcap);
}

buffer_sptr
linux_wnic::read()
{
   uint8_t octets[4096];
   struct sockaddr from;
   socklen_t from_sz = sizeof(from);
   ssize_t octets_sz = recvfrom(socket_, octets, sizeof(octets), MSG_TRUNC, &from, &from_sz);
   if(0 <= octets_sz && octets_sz <= sizeof(octets)) {
      struct sockaddr_ll *ll = reinterpret_cast<struct sockaddr_ll*>(&from);
      return dl_->parse(octets_sz, octets);
   } else if(-1 == octets_sz) {
      ostringstream msg;
      msg << "recv(socket_, octets, sizeof(octets), MSG_TRUNC): ";
      msg << strerror(errno) << endl;
      raise<syscall_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   } else {
      ostringstream msg;
      msg << "invalid size for buffer (size=" << octets_sz;
      msg << ", should be 0 < size <= " << sizeof(octets) << ")" << endl;
      raise<length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

void
linux_wnic::write(const buffer& b)
{
   uint8_t buf[b.data_size() + 1024];
   const size_t buf_sz = sizeof(buf);
   dl_->format(b, buf_sz, buf);
   ssize_t sent = send(socket_, buf, buf_sz, 0);
   if(buf_sz != sent) {
      ostringstream msg;
      msg << "send(socket_, buf, buf_sz, 0): ";
      msg << strerror(errno) << endl;
      raise<syscall_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

int
linux_wnic::datalink_type(int arp_type) const
{
   int dlt;
   switch(arp_type) {
   case ARPHRD_IEEE80211:
      dlt = DLT_IEEE802_11;
      break;
   case ARPHRD_IEEE80211_PRISM:
      dlt = DLT_PRISM_HEADER;
      break;
   case ARPHRD_IEEE80211_RADIOTAP:
      dlt = DLT_IEEE802_11_RADIO;
      break;
   default:
      ostringstream msg;
      msg << "ARPHRD 0x" << hex << arp_type << " is not a supported datalink type" << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   return dlt;
}

template <class T> int
linux_wnic::dev_ioctl(int ioctl_no, T& data) const
{
   const size_t ifr_name_sz = IFNAMSIZ;
   strncpy(data.ifr_name, name().c_str(), ifr_name_sz);
   data.ifr_name[ifr_name_sz - 1] = '\0';
   return ioctl(socket_, ioctl_no, &data);
}

#endif // __linux__
