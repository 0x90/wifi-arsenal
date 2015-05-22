#include <alloca.h>
#include <endian.h>
#include <iomanip>
#include <pcap.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace std;

void
error(const char *fmt, ...)
{
   va_list ap;
   va_start(ap, fmt);
   fputs("warning: ", stderr);
   vfprintf(stderr, fmt, ap);
   va_end(ap);
   exit(EXIT_FAILURE);
}

struct radiotap_header {
   u_int8_t it_version;         /* set to 0 */
   u_int8_t it_pad;
   u_int16_t it_len;            /* entire length */
   u_int32_t it_present;        /* fields present */
} __attribute__((__packed__));


uint16_t
radiotap_hdr_size(const uint8_t *octets, size_t octets_sz)
{
   const struct radiotap_header *radiotap;
   radiotap = (const struct radiotap_header*) octets;
   return (0 == radiotap->it_version) ? le16toh(radiotap->it_len) : 0;
}

bool
is_iperf_frame(const uint8_t *octets, size_t octets_sz)
{
   bool iperf = false;
   size_t ofs = radiotap_hdr_size(octets, octets_sz);
   if(ofs < octets_sz) {
      const uint8_t *frame = octets + ofs;
      const size_t frame_sz = octets_sz - ofs;
      if(frame[0]  == 0x88 &&                      // frame type == DATA
         frame[44] == 0x08 && frame[45] == 0x00 && // LLC type == IP
         frame[55] == 0x11 &&                      // IP protocol == UDP
         frame[68] == 0x13 && frame[69] == 0x89)   // dest port == 5959
         iperf = true;
   }
   return iperf;
}

int
main(int ac, char **av)
{
   if(ac == 2) {
      string in_path(av[1]);
      string out_path(in_path + ".new");
      string backup_path(in_path + ".orig");

      char err[PCAP_ERRBUF_SIZE];
      pcap_t *in = pcap_open_offline(in_path.c_str(), err);
      if(!in) {
         error("failed to open \"%s\" (%s)\n", in_path.c_str(), err);
      }

      const size_t MAX_BUF_SZ = 8192;
      pcap_t *dead = pcap_open_dead(pcap_datalink(in), MAX_BUF_SZ);
      if(!dead) {
         pcap_close(in);
         error("pcap_open_dead() (%s)\n");
      }

      pcap_dumper_t *out = pcap_dump_open(dead, out_path.c_str());
      if(!out) {
         pcap_close(dead);
         pcap_close(in);       
         error("failed to open \"%s\" (%s)\n", out_path.c_str(), pcap_geterr(dead));
      }

      bool iperf = false;
      const uint8_t *octets;
      struct pcap_pkthdr hdr;
      while(octets = pcap_next(in, &hdr)) {
         if(iperf || is_iperf_frame(octets, hdr.caplen)) {
            pcap_dump(reinterpret_cast<u_char*>(out), &hdr, octets);
            iperf = true;
         }
      }

      pcap_dump_close(out);
      pcap_close(dead);
      pcap_close(in);

      unlink(backup_path.c_str());
      link(in_path.c_str(), backup_path.c_str());
      unlink(in_path.c_str());
      link(out_path.c_str(), in_path.c_str());
      unlink(out_path.c_str());
   }
   exit(EXIT_SUCCESS);
}
