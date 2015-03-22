/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 *
 */

#define __STDC_LIMIT_MACROS 1

#include <dot11/frame.hpp>
#include <dot11/frame_control.hpp>
#include <net/buffer.hpp>
#include <net/buffer_info.hpp> 
#include <net/wnic.hpp>
#include <net/wnic_timestamp_fix.hpp>
#include <net/wnic_timestamp_swizzle.hpp>

#include <cstdlib>
#include <stdint.h>
#include <iomanip>
#include <iostream>
#include <unistd.h>

using namespace dot11;
using namespace net;
using namespace std;

int
main(int ac, char **av)
{
   const uint16_t SLOT = 9;
   const uint16_t SIFS = 16;
   const uint16_t DIFS = SIFS + 2 * SLOT;

   try {
      while(--ac) {

         cout << "#     ";
         cout << "TS2          ";
         cout << "Rate ";
         cout << "DUR  ";

         cout << "#     ";
         cout << "TS2           ";
         cout << "Rate ";
         cout << "DUR ";

         cout << "ΔTS  ";
         cout << "ΔDU  ";
         cout << "IFS  ";
         cout << "TXTIME ";
         cout << endl;

         wnic_sptr w = wnic::open(*++av);
         w = wnic_sptr(new wnic_timestamp_swizzle(w));
         w = wnic_sptr(new wnic_timestamp_fix(w));
         buffer_sptr n(w->read()), p;
         for(uint32_t i = 2; p = n, n = w->read(); ++i)  {
            frame pf(p);
            uint16_t p_dur = pf.duration();
            frame nf(n);
            uint16_t n_dur = nf.duration();
            if(n_dur < p_dur && 0 < p_dur) {
               uint64_t p_ts1 = p->info()->timestamp1();
               uint64_t p_ts2 = p->info()->timestamp2();
               uint32_t p_txtime = p_ts2 - p_ts1;
               uint64_t n_ts1 = n->info()->timestamp1();
               uint64_t n_ts2 = n->info()->timestamp2();
               uint32_t n_txtime = n_ts2 - n_ts1;

               uint32_t delta_ts = n_ts2 - p_ts2;
               uint32_t delta_dur = p_dur - n_dur;
               uint32_t ifs = n_ts1 - p_ts2;

               cout << setw(5)  << i - 1 << " ";
               cout << setw(12) << p_ts2 << " ";
               cout << setw(4)  << p->info()->rate_Kbs() / 1000.0 << " ";
               cout << setw(4)  << p_dur << " ";

               cout << setw(5)  << i << " ";
               cout << setw(12) << n_ts2 << " ";
               cout << setw(4)  << n->info()->rate_Kbs() / 1000.0 << " ";
               cout << setw(4)  << n_dur << " ";

               cout << setw(4)  << delta_ts << " ";
               cout << setw(4)  << delta_dur << " ";
               cout << setw(4)  << ifs << " ";
               cout << setw(4)  << p_txtime << " ";
               cout << endl;
            }
         }
      }
   } catch(const exception& x) {
      cerr << x.what() << endl;
      exit(EXIT_FAILURE);
   } catch(...) {
      cerr << "unhandled exception!" << endl;
      exit(EXIT_FAILURE);
   }
   return EXIT_SUCCESS;
}

