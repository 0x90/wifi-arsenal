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
      bool verbose;
      uint32_t dead;
      uint64_t runtime;
      string enc_str, ta_str, what;
      options_description options("program options");
      options.add_options()
         ("help,?", "produce this help message")
         ("all,a", value<bool>(&all_traffic)->default_value(false)->zero_tokens(), "report all traffic (i.e. not just iperf)")
         ("dead,d", value<uint32_t>(&dead)->default_value(0), "dead time")
         ("encoding,e", value<string>(&enc_str)->default_value("OFDM"), "channel encoding")
         ("input,i", value<string>(&what)->default_value("mon0"), "input file/device name")
         ("runtime,u", value<uint64_t>(&runtime)->default_value(0), "finish after n seconds")
         ("ta,t", value<string>(&ta_str)->default_value("48:5d:60:7c:ce:68"), "transmitter address")
         ("verbose,v", value<bool>(&verbose)->default_value(false)->zero_tokens(), "enable verbose output")
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
      buffer_sptr first(w->read());
      if(first) {
         uint64_t tick_time = UINT64_C(1000000);
         uint64_t end_time = runtime ? first->info()->timestamp_wallclock() + (runtime * tick_time) : UINT64_MAX;

         frame f(first);
         frame_control fc(f.fc());
         frame_type pt(fc.type());
         uint_least32_t t_dead = 0;
         uint_least32_t t_mgmt = 0, t_mgmt_ifs_exp = 0, t_mgmt_ifs_act = 0;
         uint_least32_t t_data = 0, t_data_ifs_exp = 0, t_data_ifs_act = 0, t_data_ifs_bcn = 0;
         uint_least32_t t_ctrl = 0, t_ctrl_ifs_exp = 0, t_ctrl_ifs_act = 0;

         buffer_sptr b(first), p, s, null;
         for(uint32_t n = 1; b && (b->info()->timestamp_wallclock() <= end_time); p = b, b = w->read(), ++n) {

            frame f(b);
            frame_control fc(f.fc());
            frame_type ft(fc.type());
            uint16_t ifs = p ? b->info()->timestamp1() - p->info()->timestamp2() : 0;
            uint16_t txtime = b->info()->timestamp2() - b->info()->timestamp1();
            encoding_sptr enc(b->info()->channel_encoding());
            const uint16_t SIFS = enc->SIFS();
            const uint16_t AIFS = enc->SIFS() + (3 * enc->slot_time());

            if(pt == MGMT_FRAME) {
               t_dead += s ? b->info()->timestamp1() - s->info()->timestamp2() : 0;
            }

            switch(ft) {
            case MGMT_FRAME:
               t_mgmt += txtime;
               t_mgmt_ifs_act += ifs;
               t_mgmt_ifs_exp += AIFS;
               s = p;
               break;
            case DATA_FRAME:
               if(!all_traffic) {
                  data_frame_sptr df(f.as_data_frame());
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
               t_data += txtime;
               t_data_ifs_act += ifs;
               t_data_ifs_exp += AIFS;
               break;
            case CTRL_FRAME:
               t_ctrl += txtime;
               t_ctrl_ifs_act += ifs;
               t_ctrl_ifs_exp += SIFS;
               break;
            default:
               break;
            }
         }

         cout << "t_mgmt=" << t_mgmt << endl;
         cout << "   ifs=" << t_mgmt_ifs_act << endl;
         cout << "   exp=" << t_mgmt_ifs_exp << endl;
         cout << endl;
         cout << "t_data=" << t_data << endl;
         cout << "   ifs=" << t_data_ifs_act << endl;
         cout << "   exp=" << t_data_ifs_exp << endl;
         cout << endl;
         cout << " t_ctl=" << t_ctrl << endl;
         cout << "   ifs=" << t_ctrl_ifs_act << endl;
         cout << "   exp=" << t_ctrl_ifs_exp << endl;
         cout << endl;

         if(b)
            cout << "elapsed=" << b->info()->timestamp2() - first->info()->timestamp1() << endl;
         else
            cout << "elapsed=" << p->info()->timestamp2() - first->info()->timestamp1() << endl;

         cout << "total_act=" << t_mgmt + t_mgmt_ifs_act + t_data + t_data_ifs_act + t_ctrl + t_ctrl_ifs_act << endl;
         cout << "total_exp=" << t_mgmt + t_mgmt_ifs_exp + t_data + t_data_ifs_exp + t_ctrl + t_ctrl_ifs_exp << endl;
         cout << " total_us=" << t_data + t_data_ifs_exp + t_ctrl + t_ctrl_ifs_exp + dead << endl;
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
