/* -*- Mode: C++; tab-width: 3; -*- */

/* 
 * Copyright NICTA, 2011
 */

#define __STDC_LIMIT_MACROS
#include <net/buffer_info.hpp>
#include <net/wnic.hpp>
#include <net/wnic_encoding_fix.hpp>
#include <net/wnic_timestamp_fix.hpp>
#include <net/wnic_timestamp_swizzle.hpp>
#include <dot11/data_frame.hpp>
#include <dot11/frame.hpp>
#include <dot11/ip_hdr.hpp>

#include <boost/program_options.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <unistd.h>

using namespace boost;
using namespace boost::program_options;
using namespace dot11;
using namespace net;
using namespace std;

int
main(int ac, char **av)
{
   try {

      string what;
      uint16_t port;
      bool use_sexprs;
      options_description options("program options");
      options.add_options()
         ("help,?", "produce this help message")
         ("input,i", value<string>(&what)->default_value("mon0"), "input file/device name")
         ("port,p", value<uint16_t>(&port)->default_value(5959), "port number")
         ;

      variables_map vars;       
      store(parse_command_line(ac, av, options), vars);
      notify(vars);   

      if(vars.count("help")) {
         cout << options << endl;
         exit(EXIT_SUCCESS);
      }

      wnic_sptr w(wnic::open(what));
      w = wnic_sptr(new wnic_encoding_fix(w, CHANNEL_CODING_OFDM | CHANNEL_PREAMBLE_LONG));
      buffer_sptr b(w->read()), first(b);
      for(uint32_t n = 1; b; b = w->read(), ++n){
         frame f(b);
         data_frame_sptr df(f.as_data_frame());
         if(!df)
            continue;
         llc_hdr_sptr llc(df->get_llc_hdr());
         if(!llc)
            continue;
         ip_hdr_sptr ip(llc->get_ip_hdr());
         if(!ip) 
            continue;
         udp_hdr_sptr udp(ip->get_udp_hdr());
         if(!udp)
            continue;
         if(udp->dst_port() != port)
            continue;
         buffer_sptr pkt(udp->get_payload());
         if(pkt->read_u8(0) == 0x3)
            cout << n << " " << b->info()->timestamp_wallclock() - first->info()->timestamp_wallclock() << " " << static_cast<uint16_t>(pkt->read_u8(1)) << endl;
      }

   } catch(const error& x) {
      cerr << x.what() << endl;
   } catch(const std::exception& x) {
      cerr << x.what() << endl;
   } catch(...) {
      cerr << "unhandled exception!" << endl;
   }
   exit(EXIT_FAILURE);
}
