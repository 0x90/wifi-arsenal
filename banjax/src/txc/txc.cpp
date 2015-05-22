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

#include <boost/program_options.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <vector>

using namespace boost;
using namespace boost::program_options;
using namespace dot11;
using namespace net;
using namespace std;

void
update(uint16_t txc, vector<double>& slots)
{
   for(uint16_t i = 0; i < txc; ++i) {
      uint16_t cw = min(1 << 4 + i, 1024);
      double p = 1.0 / cw;
      for(uint16_t j = 0; j < cw; ++j) {	
         slots[j] += p;
      }
   }
}

int
main(int ac, char **av)
{
   try {
      uint64_t runtime;
      string what, enc_str;
      bool debug, dist, stats, use_sexprs, verbose;
      options_description options("program options");
      options.add_options()
         ("help,?", "produce this help message")
         ("debug,g", value<bool>(&debug)->default_value(false)->zero_tokens(), "enable debug")
         ("dist,d", value<bool>(&dist)->default_value(false)->zero_tokens(), "show tx distribution")
         ("encoding,e", value<string>(&enc_str)->default_value("OFDM"), "channel encoding")
         ("input,i", value<string>(&what)->default_value("mon0"), "input file/device name")
         ("runtime,u", value<uint64_t>(&runtime)->default_value(0), "produce results after n seconds")
         ("stats,s", value<bool>(&stats)->default_value(false)->zero_tokens(), "show txc stats")
         ("verbose,v", value<bool>(&verbose)->default_value(false)->zero_tokens(), "show TXC per packet")
         ;
      variables_map vars;       
      store(parse_command_line(ac, av, options), vars);
      notify(vars);   
      if(vars.count("help")) {
         cout << options << endl;
         exit(EXIT_SUCCESS);
      }

      wnic_sptr w(wnic::open(what));
      vector<double> slots(1024);
      buffer_sptr b(w->read());
      if(b) {
         uint64_t tick_time = UINT64_C(1000000);
         uint64_t end_time = runtime ? b->info()->timestamp_wallclock() + (runtime * tick_time) : UINT64_MAX;
         uint_least32_t nof_txs = 0, nof_pkts = 0, max_txc = 0, min_txc = UINT32_MAX;
         for(uint32_t n = 1; b && (b->info()->timestamp_wallclock() <= end_time); b = w->read(), ++n) {
            frame f(b);
            buffer_info_sptr info(b->info());

            // use only iperf traffic!
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

            if(udp->dst_port() != 5001)
               continue;

            if(info->has(TX_FLAGS) && info->has(DATA_RETRIES)) {
               uint txc = 1 + info->data_retries();
               max_txc = max(max_txc, txc);
               min_txc = min(min_txc, txc);
               nof_txs += txc;
               ++nof_pkts;
               update(txc, slots);
               if(verbose)
                  cout << n << " " << txc << endl;
            }
            if(debug)
               cout << n << " " << *info << endl;
         }
         if(dist) {
            for(uint32_t i = 0; i < min(static_cast<uint32_t>(slots.size()), static_cast<uint32_t>(1 << 4 + max_txc - 1)); ++i) {
               cout << i << " " << slots[i] << endl;
            }
         }
         if(stats) {
            cout << "txc: " << nof_txs / static_cast<double>(nof_pkts) << ", ";
            cout << "nof_pkts: " << nof_pkts << ", ";
            cout << "nof_txs: " << nof_txs << ", ";
            cout << "min txc: " << min_txc << ", ";
            cout << "max txc: " << max_txc << endl;
         }
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
