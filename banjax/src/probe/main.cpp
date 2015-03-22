/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright NICTA, 2011
 */

#define __STDC_LIMIT_MACROS ON
#include <wireless_link_monitor.hpp>
#include <timespec.hpp>

#include <boost/program_options.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>

using namespace boost::program_options;
using namespace ETX;
using namespace std;

/**
 * <tt>main(int,char**)</tt> function for the ETX link-quality
 * monitor.
 *
 * \param ac The argument count.
 * \param av The argument vector (use "--help" to list all options).
 * \return Does not return. Calls <tt>exit()</tt> with either EXIT_SUCCESS or EXIT_FAILURE.
 */
int
main(int ac, char **av)
{
   try {

      uint16_t delay_s;
      uint16_t port_no;
      uint16_t probe_sz;
      uint16_t window_sz;
      uint32_t duration_s;
      string bind_str;
      bool verbose;

      options_description options("program options");
      options.add_options()
         ("help,?", "produce this help message")
         ("bind,b", value<string>(&bind_str)->default_value("255.255.255.255"), "address of interface to bind to")
         ("delay,d", value<uint16_t>(&delay_s)->default_value(1), "delay between probes (in seconds)")
         ("port,p", value<uint16_t>(&port_no)->default_value(50000), "port number")
         ("size,s", value<uint16_t>(&probe_sz)->default_value(134), "size of probe packets (in octets)")
         ("time,t", value<uint32_t>(&duration_s)->default_value(UINT32_MAX), "duration to run for (in seconds)")
         ("verbose,v", value<bool>(&verbose)->zero_tokens(), "turn on verbose output")
         ("window,w", value<uint16_t>(&window_sz)->default_value(10), "size of the probe window (in seconds)")
         ;

      variables_map vars;
      store(parse_command_line(ac, av, options), vars);
      notify(vars);   
      if(vars.count("help")) {
         cout << options << endl;
         exit(EXIT_SUCCESS);
      }

      wireless_link_monitor m(bind_str, port_no, probe_sz, window_sz, delay_s, verbose);
      m.run(duration_s);
      exit(EXIT_SUCCESS);

   } catch(const error& x) {
      cerr << x.what() << endl;
   } catch(const std::exception& x) {
      cerr << x.what() << endl;
   } catch(...) {
      cerr << "unhandled exception!" << endl;
   }
   exit(EXIT_FAILURE);
}
