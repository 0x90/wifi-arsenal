/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#include <net/encoding.hpp>
#include <util/exceptions.hpp>

#include <iomanip>
#include <iostream>

using namespace net;
using namespace std;

encoding::~encoding()
{
}

uint16_t
encoding::CWMAX() const
{
   return 1023;
}

uint16_t
encoding::DIFS() const
{
   return SIFS() + (2 * slot_time());
}

uint32_t
encoding::default_rate() const
{
   return *(basic_rates().begin());
}

bool
encoding::is_legal_rate(uint32_t rate_Kbs) const
{
   rateset rates(supported_rates());
   return(rates.find(rate_Kbs) != rates.end());
}


uint32_t
encoding::response_rate(uint32_t rate_Kbs) const
{
   CHECK(is_legal_rate(rate_Kbs));

   rateset rates(basic_rates());
   uint32_t response_rate = *(rates.begin());
   for(rateset::const_iterator i(rates.begin()); i != rates.end(); ++i) {
      if(*i <= rate_Kbs) {
         response_rate = *i;
      } else
         break;
   }
   return response_rate;
}

void
encoding::write(ostream& os) const
{
   os << "encoding: " << name() << ", ";
   os << "slot time: " << slot_time() << ", ";
   os << "SIFS: " << SIFS() << ", ";
   os << "DIFS: " << DIFS() << ", ";
   os << "CWMIN: " << CWMIN() << ", ";
   os << "CWMAX: " << CWMAX() << ", ";

   os << "RATES: ";
   uint32_t d = default_rate();
   rateset rates(supported_rates());
   rateset::const_iterator i(rates.begin());
   if(i != rates.end()) {
      os << *i;
      while(++i != rates.end()) {
         os << "|" << (*i * 1000);
         if(*i == d) {
            os << "*";
         }
      }
   }
   os << ", ";

}

encoding::encoding()
{
}
