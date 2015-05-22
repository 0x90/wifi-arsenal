/* -*- Mode: C++; tab-width: 3; -*- */

/* 
 * Copyright NICTA, 2011
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <dot11/data_frame.hpp>
#include <dot11/frame.hpp>
#include <dot11/ip_hdr.hpp>
#include <dot11/llc_hdr.hpp>
#include <dot11/udp_hdr.hpp>
#include <net/buffer_info.hpp>
#include <net/wnic.hpp>
#include <net/wnic_encoding_fix.hpp>
#include <net/wnic_timestamp_fix.hpp>
#include <net/wnic_timestamp_swizzle.hpp>
#include <dot11/frame.hpp>

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

      bool debug;
      bool all_traffic;
      uint64_t runtime;
      string enc_str, ta_str, what;
      options_description options("program options");
      options.add_options()
         ("help,?", "produce this help message")
         ("all,a", value<bool>(&all_traffic)->default_value(false)->zero_tokens(), "report all traffic (i.e. not just iperf)")
         ("encoding,e", value<string>(&enc_str)->default_value("OFDM"), "channel encoding")
         ("input,i", value<string>(&what)->default_value("mon0"), "input file/device name")
         ("runtime,u", value<uint64_t>(&runtime)->default_value(0), "finish after n seconds")
         ("ta,t", value<string>(&ta_str)->default_value("48:5d:60:7c:ce:68"), "transmitter address")
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
      w = wnic_sptr(new wnic_timestamp_swizzle(w));
      w = wnic_sptr(new wnic_timestamp_fix(w));
      encoding_sptr enc(encoding::get(enc_str));

      eui_48 ta(ta_str.c_str());
      uint16_t txc = 0, seq_no = 0;
      uint_least32_t n_cw = 0, t_cw = 0;
      buffer_sptr b(w->read()), p, null;
      if(b) {
         uint64_t tick_time = UINT64_C(1000000);
         uint64_t end_time = runtime ? b->info()->timestamp_wallclock() + (runtime * tick_time) : UINT64_MAX;
         for(uint32_t n = 1; b && (b->info()->timestamp_wallclock() <= end_time); p = b, b = w->read(), ++n) {
            frame f(b);
            frame_control fc(f.fc());

            // use only iperf traffic!
            data_frame_sptr df(f.as_data_frame());
            if(!df)
               continue;

            if(!all_traffic) {
               llc_hdr_sptr llc(df->get_llc_hdr());
               if(!llc)
                  continue;
               ip_hdr_sptr ip(llc->get_ip_hdr());
               if(!ip)
                  continue;
               udp_hdr_sptr udp(ip->get_udp_hdr());
               if(!udp)
                  continue;
               if(udp->dst_port() != 5001)
                  continue;
            }

            if(p && f.address2() == ta) {
               uint16_t ifs;
               if(!fc.retry()) {
                  txc = 0;
                  seq_no = f.sc().sequence_no();
                  ifs = b->info()->timestamp1() - p->info()->timestamp2();
                  ++n_cw;
                  t_cw += ifs;
                  cout << n << " " << b->info()->timestamp1() << " " << ifs << " " << txc << endl;
               } else if(fc.retry() && f.sc().sequence_no() == seq_no) {
                  ++txc;
                  ifs = b->info()->timestamp1() - p->info()->timestamp2();
                  ++n_cw;
                  t_cw += ifs;
                  cout << n << " " << b->info()->timestamp1() << " " << ifs << " " << txc << endl;
               }
            }
         }
      }
      cerr << "AVG CONTENTION TIME = " << (t_cw / static_cast<double>(n_cw)) - enc->DIFS() << endl;

   } catch(const error& x) {
      cerr << x.what() << endl;
   } catch(const std::exception& x) {
      cerr << x.what() << endl;
   } catch(...) {
      cerr << "unhandled exception!" << endl;
   }
   exit(EXIT_FAILURE);
}
