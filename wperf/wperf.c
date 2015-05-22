#define _BSD_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <endian.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

/* The default server UDP port */
#define PORT  8888

/* The default MTU in bytes */
#define MTU  1500

/* The default printout interval in seconds */
#define INTERVAL  1

/* The default send bitrate in bit/s */
#define BITRATE  1000000

/* The maximum packet size */
#define BUFSIZE  8192

/* The packet headroom reserved headers in monitor mode */
#define HEADROOM  256

/* The receive window size in packets */
#define WINDOW  8192

/* The maximum number of packets sent in a burst */
#define BURST 100

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Radiotap definitions */
#define RADIOTAP_TSFT  0
#define RADIOTAP_FLAGS 1

#define RADIOTAP_F_WEP        0x04
#define RADIOTAP_F_FCS_FAILED 0x40

struct radiotap_hdr {
    uint8_t  version;
    uint8_t  pad;
    uint16_t length;
    uint32_t present;
} __attribute__((packed));

/* IEEE 802.11 definitions */
#define IEEE80211_FC_VERSION   0x0003
#define IEEE80211_FC_TYPE      0x000c
#define IEEE80211_FC_SUBTYPE   0x0070
#define IEEE80211_FC_QOS       0x0080
#define IEEE80211_FC_TODS      0x0100
#define IEEE80211_FC_FROMDS    0x0200
#define IEEE80211_FC_PROTECTED 0x4000

#define IEEE80211_FC_TYPE_DATA    (2 << 2)
#define IEEE80211_FC_SUBTYPE_DATA (0 << 4)

#define IEEE80211_IV_LEN    4
#define IEEE80211_EXTIV_LEN 4
#define IEEE80211_HAS_EXTIV 0x20

struct ieee80211_hdr {
    uint16_t          frame_ctl;
    uint16_t          duration;
    struct ether_addr addr1;
    struct ether_addr addr2;
    struct ether_addr addr3;
    uint16_t          seq_ctl;
} __attribute__((packed));

struct ieee80211_qoshdr {
    uint16_t          frame_ctl;
    uint16_t          duration;
    struct ether_addr addr1;
    struct ether_addr addr2;
    struct ether_addr addr3;
    uint16_t          seq_ctl;
    uint16_t          qos_ctl;
} __attribute__((packed));

/* LLC definitions */
struct llc_snap {
    uint8_t  dsap;
    uint8_t  ssap;
    uint8_t  control;
    uint8_t  oui[3];
    uint16_t type;
} __attribute__((packed));

struct options {
    struct sockaddr_in server;
    struct ether_addr  dhost;
    struct ether_addr  shost;
    struct ether_addr  bssid;
    const char        *monitor;
    uint64_t           bitrate;
    unsigned           interval;
    unsigned           mtu;
    int                tid;
    bool               isserver;
    bool               isclient;
    bool               issta;
};

static volatile bool g_report;

static int
open_monitor(const char *ifname)
{
    struct sockaddr_ll ll;
    int sock;

    memset(&ll, 0, sizeof ll);
    ll.sll_family = AF_PACKET;
    ll.sll_ifindex = if_nametoindex(ifname);

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr*)&ll, sizeof ll) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    return sock;
}

static int
open_udp(int port)
{
    struct sockaddr_in sa;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    return sock;
}

static void
connect_udp(int sock, const struct sockaddr_in *peer, struct sockaddr_in *src)
{
    socklen_t addrlen = sizeof *src;

    if (connect(sock, (struct sockaddr*)peer, sizeof *peer) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    if (getsockname(sock, (struct sockaddr*)src, &addrlen) < 0) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
}

static unsigned
checksum(unsigned csum, const uint8_t *buf, size_t len)
{
    size_t k;
    uint16_t val;

    for (k = 0; k < (len & ~1); k += 2) {
        memcpy(&val, &buf[k], 2);
        csum += val;
    }
    if (len & 1) {
        uint8_t last[2] = {buf[len - 1], 0};
        memcpy(&val, last, 2);
        csum += val;
    }
    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return csum;
}

static int
encap_radiotap(uint8_t *buf, size_t pos, size_t len)
{
    struct radiotap_hdr *rthdr = (void*)&buf[pos - sizeof *rthdr - 1];

    (void)len;
    assert(pos >= sizeof *rthdr + 1 /* flags */);
    rthdr->version = 0;
    rthdr->pad = 0;
    rthdr->length = htole16(sizeof *rthdr + 1);
    rthdr->present = htole32(1 << RADIOTAP_FLAGS);
    buf[pos - 1] = RADIOTAP_F_WEP;
    return pos - sizeof *rthdr - 1;
}

static int
decap_radiotap(uint8_t *buf, size_t pos, size_t len)
{
    struct radiotap_hdr *rthdr = (void*)&buf[pos];
    size_t rtmask, rtlen;

    /* Validate the Radiotap header size */
    if (len < pos + sizeof *rthdr) {
        return -1;
    }
    rtlen = le16toh(rthdr->length);
    rtmask = le32toh(rthdr->present);
    if (len < pos + rtlen) {
        return -1;
    }

    /* Discard frames with FCS error */
    if (rtmask & (1 << RADIOTAP_FLAGS)) {
        size_t idx = pos + sizeof *rthdr;
        if (rtmask & (1 << RADIOTAP_TSFT)) {
            idx += 8;
        }
        if (idx >= len || (buf[idx] & RADIOTAP_F_FCS_FAILED)) {
            return -1;
        }
    }

    return pos + rtlen;
}

static int
encap_80211(uint8_t *buf, size_t pos, size_t len,
            const struct ether_addr *dhost, const struct ether_addr *shost,
            const struct ether_addr *bssid, int tid, bool tods)
{
    struct ieee80211_qoshdr *machdr;
    size_t maclen;
    unsigned fc;

    (void)len;
    assert(pos >= sizeof *machdr);

    fc = IEEE80211_FC_TYPE_DATA | IEEE80211_FC_SUBTYPE_DATA;
    if (tid >= 0) {
        maclen = sizeof(struct ieee80211_qoshdr);
        machdr = (void*)&buf[pos - maclen];
        machdr->qos_ctl = htole16(tid & 0xf);
        fc |= IEEE80211_FC_QOS;
    }
    else {
        maclen = sizeof(struct ieee80211_hdr);
        machdr = (void*)&buf[pos - maclen];
    }
    if (tods) {
        fc |= IEEE80211_FC_TODS;
        machdr->addr1 = *bssid;
        machdr->addr2 = *shost;
        machdr->addr3 = *dhost;
    }
    else {
        fc |= IEEE80211_FC_FROMDS;
        machdr->addr1 = *dhost;
        machdr->addr2 = *bssid;
        machdr->addr3 = *shost;
    }

    machdr->frame_ctl = htole16(fc);
    machdr->duration = 0;
    machdr->seq_ctl = 0;
    return pos - maclen;
}

static int
decap_80211(uint8_t *buf, size_t pos, size_t len,
            const struct ether_addr **dhost, const struct ether_addr **shost,
            const struct ether_addr **bssid, bool tods)
{
    struct ieee80211_qoshdr *machdr = (void*)&buf[pos];
    size_t maclen = sizeof(struct ieee80211_hdr);
    size_t ivlen = 0;
    unsigned fc;

    if (pos + sizeof(struct ieee80211_hdr) > len) {
        return -1;
    }

    fc = le16toh(machdr->frame_ctl);
    if (fc & IEEE80211_FC_QOS) {
        maclen += 2;
    }
    if ((fc & IEEE80211_FC_TYPE) != IEEE80211_FC_TYPE_DATA ||
        (fc & IEEE80211_FC_SUBTYPE) != IEEE80211_FC_SUBTYPE_DATA)
    {
        return -1;
    }
    if ((tods && (fc & IEEE80211_FC_TODS) == 0) ||
        (!tods && (fc & IEEE80211_FC_FROMDS) == 0))
    {
        return -1;
    }
    if (fc & IEEE80211_FC_PROTECTED) {
        uint8_t *iv = &buf[pos + maclen];

        ivlen = IEEE80211_IV_LEN;
        if (pos + maclen + ivlen > len) {
            return -1;
        }
        if (iv[3] & IEEE80211_HAS_EXTIV) {
            ivlen += IEEE80211_EXTIV_LEN;
            if (pos + maclen + ivlen > len) {
                return -1;
            }
        }
    }

    if (tods) {
        *bssid = &machdr->addr1;
        *shost = &machdr->addr2;
        *dhost = &machdr->addr3;
    }
    else {
        *dhost = &machdr->addr1;
        *bssid = &machdr->addr2;
        *shost = &machdr->addr3;
    }
    return pos + maclen + ivlen;
}

static int
encap_llc(uint8_t *buf, size_t pos, size_t len, unsigned ether_type)
{
    struct llc_snap *llc = (void*)&buf[pos - sizeof *llc];

    (void)len;
    assert(pos >= sizeof *llc);
    llc->dsap = 0xaa;
    llc->ssap = 0xaa;
    llc->control = 3;
    llc->type = htons(ether_type);
    return pos - sizeof *llc;
}

static int
decap_llc(uint8_t *buf, size_t pos, size_t len, unsigned *ether_type)
{
    struct llc_snap *llc = (void*)&buf[pos];

    if (pos + sizeof *llc > len) {
        return -1;
    }

    *ether_type = ntohs(llc->type);
    return pos + sizeof *llc;
}

static int
encap_ip(uint8_t *buf, size_t pos, size_t len, int proto,
         const struct in_addr *daddr, const struct in_addr *saddr)
{
    struct ip *iphdr = (void*)&buf[pos - sizeof *iphdr];
    static unsigned g_ipcounter = 0;

    assert(pos >= sizeof *iphdr);
    memset(iphdr, 0, sizeof *iphdr);
    iphdr->ip_hl = sizeof *iphdr / 4;
    iphdr->ip_v = IPVERSION;
    iphdr->ip_len = htons(len - pos + sizeof *iphdr);
    iphdr->ip_id = htons(g_ipcounter++);
    iphdr->ip_ttl = 64;
    iphdr->ip_p = proto;
    memcpy(&iphdr->ip_src, saddr, sizeof(struct in_addr));
    memcpy(&iphdr->ip_dst, daddr, sizeof(struct in_addr));
    iphdr->ip_sum = ~checksum(0, (void*)iphdr, sizeof *iphdr);
    return pos - sizeof *iphdr;
}

static int
decap_ip(uint8_t *buf, size_t pos, size_t len, unsigned *proto, size_t *bytes,
         const struct in_addr **daddr, const struct in_addr **saddr)
{
    struct ip *iphdr = (void*)&buf[pos];
    size_t hlen, plen;

    if (pos + sizeof *iphdr > len) {
        return -1;
    }

    hlen = 4 * iphdr->ip_hl;
    plen = ntohs(iphdr->ip_len);

    if (pos + hlen > len || hlen < sizeof *iphdr / 4) {
        return -1;
    }
    if (pos + plen > len || plen < hlen) {
        return -1;
    }
    if (iphdr->ip_v != IPVERSION) {
        return -1;
    }
    if ((iphdr->ip_off & ~htons(IP_DF)) != 0) {
        return -1;
    }

    *proto = iphdr->ip_p;
    *bytes = plen - hlen;
    *daddr = &iphdr->ip_dst;
    *saddr = &iphdr->ip_src;
    return pos + 4 * iphdr->ip_hl;
}

static int
encap_udp(uint8_t *buf, size_t pos, size_t len,
          in_port_t dport, in_port_t sport)
{
    struct udphdr *udphdr = (void*)&buf[pos - sizeof *udphdr];

    assert(pos >= sizeof *udphdr);
    udphdr->uh_sport = sport;
    udphdr->uh_dport = dport;
    udphdr->uh_ulen = htons(len - pos + sizeof *udphdr);
    udphdr->uh_sum = 0;
    return pos - sizeof *udphdr;
}

static int
decap_udp(uint8_t *buf, size_t pos, size_t len,
          size_t *bytes, in_port_t *dport, in_port_t *sport)
{
    struct udphdr *udphdr = (void*)&buf[pos];
    size_t ulen;

    if (pos + sizeof *udphdr > len) {
        return -1;
    }

    ulen = ntohs(udphdr->uh_ulen);
    if (pos + ulen > len || ulen < sizeof *udphdr) {
        return -1;
    }

    *bytes = ulen - sizeof *udphdr;
    *dport = udphdr->uh_dport;
    *sport = udphdr->uh_sport;
    return pos + sizeof *udphdr;
}

static void
round_dec(struct timeval *tv, int decimals)
{
    static const unsigned divisors[] = {
        1000000, 100000, 10000, 1000, 100, 10, 1
    };

    unsigned div = divisors[MIN(decimals, 6)];

    tv->tv_usec += div / 2;
    tv->tv_sec += tv->tv_usec / 1000000;
    tv->tv_usec = tv->tv_usec % 1000000 / div;
}

static const char*
print_volume(uint64_t vol, char *buf, size_t len)
{
    const char *suffix = "";
    float value = vol;

    if (vol < 1000000) {
        suffix = "ki";
        value = vol / 1000.0f;
    }
    else if (vol < 1000000000U) {
        suffix = "Mi";
        value = vol / 1000000.0f;
    }
    else {
        suffix = "Gi";
        value = vol / 1000000000.0f;
    }

    snprintf(buf, len, "%6.2f %s", value, suffix);
    return buf;
}

static void
safe_usleep(unsigned usec)
{
    struct timespec req = {
        .tv_sec = usec / 1000000,
        .tv_nsec = (usec % 1000000) * 1000,
    };
    while (nanosleep(&req, &req) < 0 && errno == EINTR) {
        ;
    }
}

static void
run_server(int sock, bool ismonitor,
           const struct sockaddr_in *dst, const struct sockaddr_in *src,
           const struct ether_addr *dhost, const struct ether_addr *shost,
           const struct ether_addr *bssid, bool tods)
{
    struct timeval reported_at;
    static uint8_t g_buffer[BUFSIZE];
    static uint32_t rx_window[WINDOW];
    uint32_t rx_packets = 0;
    uint32_t rx_drops = 0;
    uint64_t rx_bytes = 0;

    gettimeofday(&reported_at, NULL);

    for (;;) {
        uint8_t *buf = g_buffer;
        uint32_t seq, old;
        int len;

        /* Receive the next packet */
        len = recv(sock, g_buffer, sizeof g_buffer, 0);

        /* Handle the report event signal */
        if (g_report) {
            struct timeval elapsed;
            struct timeval now;
            uint64_t bps;
            uint32_t usecs;
            char tmp[2][32];

            g_report = false;
            gettimeofday(&now, NULL);
            timersub(&now, &reported_at, &elapsed);

            usecs = 1000000 * elapsed.tv_sec + elapsed.tv_usec;
            bps = 8000000ULL * rx_bytes / (uint64_t)usecs;
            round_dec(&elapsed, 2);

            printf("Rx %sB %6u pkts %6u drops (%5.2f%%)"
                   " in %lu.%02lus rate %sbit/s\n",
                   print_volume(rx_bytes, tmp[0], sizeof *tmp),
                   rx_packets, rx_drops,
                   100.0f * rx_drops / (float)(MAX(rx_packets + rx_drops, 1)),
                   elapsed.tv_sec, elapsed.tv_usec,
                   print_volume(bps, tmp[1], sizeof *tmp));
            reported_at = now;
            rx_packets = 0;
            rx_drops = 0;
            rx_bytes = 0;
        }
        if (len < 0) {
            continue;
        }

        /* Rip off the Radiotap/802.11/LLC/IP/UDP headers for monitor recv */
        if (ismonitor) {
            const struct ether_addr *dh, *sh, *bs;
            const struct in_addr *da, *sa;
            in_port_t dp, sp;
            unsigned proto, etype;
            size_t bytes;
            int pos = 0;

            if ((pos = decap_radiotap(buf, pos, len)) < 0) {
                continue;
            }

            pos = decap_80211(buf, pos, len, &dh, &sh, &bs, tods);
            if (pos < 0 ||
                (dhost && memcmp(dh, dhost, sizeof *dhost) != 0) ||
                (shost && memcmp(sh, shost, sizeof *shost) != 0) ||
                (bssid && memcmp(bs, bssid, sizeof *bssid) != 0))
            {
                continue;
            }

            pos = decap_llc(buf, pos, len, &etype);
            if (pos < 0 || etype != ETHERTYPE_IP) {
                continue;
            }

            pos = decap_ip(buf, pos, len, &proto, &bytes, &da, &sa);
            len = pos + bytes;
            if (pos < 0 ||
                proto != IPPROTO_UDP ||
                (dst && dst->sin_addr.s_addr != htonl(INADDR_ANY) &&
                 memcmp(da, &dst->sin_addr, sizeof *dst) != 0) ||
                (src && src->sin_addr.s_addr != htonl(INADDR_ANY) &&
                 memcmp(sa, &src->sin_addr, sizeof *src) != 0))
            {
                continue;
            }

            pos = decap_udp(buf, pos, len, &bytes, &dp, &sp);
            len = pos + bytes;
            if (pos < 0 ||
                (dst && dst->sin_port != 0 && dst->sin_port != dp) ||
                (src && src->sin_port != 0 && src->sin_port != sp))
            {
                continue;
            }

            buf += pos;
            len -= pos;
        }

        /* The sequence number must fit */
        if (len < (int)sizeof seq) {
            continue;
        }

        /* Account the received packet: record packet loss and discard dups */
        memcpy(&seq, buf, sizeof seq);
        seq = ntohl(seq);
        old = rx_window[seq % WINDOW];
        rx_window[seq % WINDOW] = seq;

        if (seq == 0) {
            memset(rx_window, 0, sizeof rx_window);
        }
        else if (old != 0 && seq > old) {
            rx_drops += (seq - old) / WINDOW - 1;
        }
        if (seq != old) {
            rx_packets++;
            rx_bytes += len + sizeof(struct ip) + sizeof(struct udphdr);
        }
    }
}

static void
run_client(int sock, bool ismonitor, size_t payload, uint64_t rate,
           const struct sockaddr_in *dst, const struct sockaddr_in *src,
           const struct ether_addr *dhost, const struct ether_addr *shost,
           const struct ether_addr *bssid, int tid, bool tods)
{
    struct timeval reported_at;
    struct timeval updated_at;
    static uint8_t g_buffer[BUFSIZE];
    uint32_t seqnum = 0;
    uint32_t tx_packets = 0;
    uint64_t tx_bytes = 0;
    int64_t error = 0;
    unsigned tick;

    gettimeofday(&reported_at, NULL);
    gettimeofday(&updated_at, NULL);

    /* Compute the tick value in microseconds. Try to burst BURST packets,
     * but don't wait longer than 10ms for the next burst.
     */
    tick = 1000000ULL * (payload + sizeof(struct ip) +
                         sizeof(struct udphdr)) / rate;
    tick = MAX(tick, MIN(BURST * tick, 10000));

    for (;;) {
        struct timeval now;
        struct timeval elapsed;
        uint8_t *buf = g_buffer;
        int pos = HEADROOM;
        int len = HEADROOM + payload;
        int bytes, ret;

        /* Sequence the UDP packets */
        *(uint32_t*)&buf[pos] = htonl(seqnum++);

        /* Add Radiotap/802.11/LLC/IP/UDP headers for monitor transmission */
        if (ismonitor) {
            pos = encap_udp(buf, pos, len, dst->sin_port, src->sin_port);
            pos = encap_ip(buf, pos, len, IPPROTO_UDP,
                           &dst->sin_addr, &src->sin_addr);
            pos = encap_llc(buf, pos, len, ETHERTYPE_IP);
            pos = encap_80211(buf, pos, len, dhost, shost, bssid, tid, tods);
            pos = encap_radiotap(buf, pos, len);
        }

        /* Send the packet */
        do {
            ret = send(sock, &buf[pos], len - pos, 0);
        } while (ret < 0 && errno == EINTR);

        /* Account the sent packet, including IP and UDP headers */
        bytes = payload + sizeof(struct ip) + sizeof(struct udphdr);
        tx_packets++;
        tx_bytes += bytes;

        gettimeofday(&now, NULL);
        timersub(&now, &updated_at, &elapsed);

        /* Update the running rate error metric: error = B - T * R */
        error += bytes * 1000000ULL;
        error -= rate * elapsed.tv_sec * 1000000ULL + rate * elapsed.tv_usec;
        updated_at = now;

        /* If sleeping for one tick would decrease the rate error, do so */
        if (llabs(error) >= llabs(error - rate * tick)) {
            safe_usleep(tick);
        }

        /* Handle the report event signal */
        if (g_report) {
            uint64_t bps;
            uint32_t usecs;
            char tmp[2][32];

            g_report = false;
            gettimeofday(&now, NULL);
            timersub(&now, &reported_at, &elapsed);

            usecs = 1000000 * elapsed.tv_sec + elapsed.tv_usec;
            bps = 8000000ULL * tx_bytes / (uint64_t)usecs;
            round_dec(&elapsed, 2);

            printf("Tx %sB %6u pkts in %lu.%02lus rate %sbit/s\n",
                   print_volume(tx_bytes, tmp[0], sizeof *tmp),
                   tx_packets, elapsed.tv_sec, elapsed.tv_usec,
                   print_volume(bps, tmp[1], sizeof *tmp));
            reported_at = now;
            tx_packets = 0;
            tx_bytes = 0;
        }
    }
}

static void
sighandler(int signo)
{
    if (signo == SIGRTMIN) {
        g_report = true;
    }
}

static uint64_t
parse_rate(const char *str)
{
    unsigned long long value = 0;
    char suffix = 0;
    char eos = 0;

    if (sscanf(str, "%llu%c%c", &value, &suffix, &eos) >= 1 && eos == 0) {
        switch (suffix) {
        case 'G':
        case 'g':
            return value * 1000000000ULL;

        case 'M':
        case 'm':
            return value * 1000000ULL;

        case 'K':
        case 'k':
            return value * 1000ULL;

        case 0:
            return value;
        }
    }

    fprintf(stderr, "Invalid bitrate %s\n", str);
    exit(EXIT_FAILURE);
}

static void
parse_mac(struct ether_addr *ea, const char *str)
{
    const struct ether_addr *tmp;

    tmp = ether_aton(str);
    if (!tmp) {
        fprintf(stderr, "Invalid MAC address %s\n", str);
        exit(EXIT_FAILURE);
    }
    *ea = *tmp;
}

static bool
mac_isempty(const struct ether_addr *ea)
{
    static const struct ether_addr empty = {{0}};
    return memcmp(ea, &empty, sizeof empty) == 0;
}

static void
usage(void)
{
    printf("Usage: wperf [-s|-c host] [options]\n"
           "       wperf [-h|--help]\n"
           "\nOptions:\n"
           "\t-p, --port     <port> server UDP port to listen on/connect to\n"
           "\t-m, --mtu      <mtu>  set the MTU size, default %u\n"
           "\t-s, --server          run in server mode\n"
           "\t-c, --client   <host> run in client mode, connecting to <host>\n"
           "\t-b, --bandwidh <bps>  set the bandwidth in [G|M|k]bit/s\n"
           "\t-M, --monitor  <if>   use a monitor interface for send/receive\n"
           "\t-D, --dhost    <mac>  dest MAC address (monitor only)\n"
           "\t-S, --shost    <mac>  source MAC address (monitor only)\n"
           "\t-B, --bssid    <mac>  AP BSSID MAC address (monitor only)\n"
           "\t-q, --tid      <tid>  set TID, -1 for non-QoS (monitor only)\n"
           "\t-t, --sta             run as STA instead of AP (monitor only)\n"
           "\t-i, --interval <sec>  set the printout interval (default %us)\n"
           "\t-h, --help            display this help and exit\n",
           MTU, INTERVAL);
}

static void
parse(int argc, char **argv, struct options *data)
{
    static const struct option opts[] = {
        {"server",         0, NULL, 's'},
        {"client",         1, NULL, 'c'},
        {"port",           1, NULL, 'p'},
        {"bandwidth",      1, NULL, 'b'},
        {"mtu",            1, NULL, 'm'},
        {"monitor",        1, NULL, 'M'},
        {"dhost",          1, NULL, 'D'},
        {"shost",          1, NULL, 'S'},
        {"bssid",          1, NULL, 'B'},
        {"sta",            0, NULL, 't'},
        {"tid",            1, NULL, 'q'},
        {"interval",       1, NULL, 'i'},
        {"help",           0, NULL, 'h'},
        {NULL,             0, NULL,   0}
    };

    int ch;

    while ((ch = getopt_long(argc, argv,
                             "sc:b:p:m:M:D:S:B:tq:i:h", opts, NULL)) != -1)
    {
        switch (ch) {
        case 's':
            data->isserver = true;
            break;

        case 'c':
            data->server.sin_addr.s_addr = inet_addr(optarg);
            data->isclient = true;
            break;

        case 'p':
            data->server.sin_port = htons(atoi(optarg));
            break;

        case 'b':
            data->bitrate = parse_rate(optarg);
            break;

        case 'm':
            data->mtu = atoi(optarg);
            break;

        case 'M':
            data->monitor = optarg;
            break;

        case 'D':
            parse_mac(&data->dhost, optarg);
            break;

        case 'S':
            parse_mac(&data->shost, optarg);
            break;

        case 'B':
            parse_mac(&data->bssid, optarg);
            break;

        case 't':
            data->issta = true;
            break;

        case 'q':
            data->tid = atoi(optarg);
            break;

        case 'i':
            data->interval = atoi(optarg);
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case '?':
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }
    argc -= optind - 1;
    argv += optind - 1;

    data->server.sin_family = AF_INET;
    if (!data->isserver &&
        !(data->isclient && data->server.sin_addr.s_addr != 0))
    {
        usage();
        exit(EXIT_FAILURE);
    }
    if (data->mtu < 4 + sizeof(struct ip) + sizeof(struct udphdr)) {
        fprintf(stderr, "MTU %u is too low\n", data->mtu);
        exit(EXIT_FAILURE);
    }
    if (data->mtu > BUFSIZE - HEADROOM -
                    sizeof(struct ip) - sizeof(struct udphdr))
    {
        fprintf(stderr, "MTU %u is too high\n", data->mtu);
        exit(EXIT_FAILURE);
    }
    if (data->monitor) {
        if (mac_isempty(&data->dhost) && (data->issta ^ data->isserver)) {
            data->dhost = data->bssid;
        }
        if (mac_isempty(&data->shost) && (data->issta ^ data->isclient)) {
            data->shost = data->bssid;
        }
        if (mac_isempty(&data->bssid)) {
            fprintf(stderr, "Monitor mode requires --bssid\n");
            exit(EXIT_FAILURE);
        }
        if (mac_isempty(&data->dhost)) {
            fprintf(stderr, "Monitor mode requires --dhost\n");
            exit(EXIT_FAILURE);
        }
        if (mac_isempty(&data->shost)) {
            fprintf(stderr, "Monitor mode requires --shost\n");
            exit(EXIT_FAILURE);
        }
    }
}

int
main(int argc, char **argv)
{
    struct options opts = {
        .server   = {
            .sin_port = htons(PORT),
            .sin_addr = {0}
        },
        .monitor  = NULL,
        .mtu      = MTU,
        .bitrate  = BITRATE,
        .interval = INTERVAL,
    };

    int usock = -1;
    int msock = -1;
    int sock, port, bytes;
    struct itimerspec intval;
    struct sigaction sigact;
    struct sigevent sigev;
    timer_t timer;

    /* Parse arguments */
    parse(argc, argv, &opts);

    /* Create sockets */
    port = opts.isserver ? htons(opts.server.sin_port) : 0;
    sock = usock = open_udp(port);
    if (opts.monitor) {
        sock = msock = open_monitor(opts.monitor);
    }

    /* Set up a sighandler to trigger printouts on SIGRTMIN */
    memset(&sigact, 0, sizeof sigact);
    sigact.sa_handler = &sighandler;
    sigaction(SIGRTMIN, &sigact, NULL);

    /* Schedule a SIGRTMIN monotonic timer */
    memset(&sigev, 0, sizeof sigev);
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;
    if (timer_create(CLOCK_MONOTONIC, &sigev, &timer) < 0) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    /* Schedule the timer to fire in 'interval' seconds */
    memset(&intval, 0, sizeof intval);
    intval.it_interval.tv_sec = opts.interval;
    intval.it_value.tv_sec = opts.interval;
    if (timer_settime(timer, 0, &intval, NULL) < 0) {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }

    /* Start send/receive data */
    bytes = opts.mtu - sizeof(struct ip) - sizeof(struct udphdr);
    if (opts.isclient) {
        struct sockaddr_in sa;
        connect_udp(usock, &opts.server, &sa);
        run_client(sock, msock >= 0, bytes, MAX(opts.bitrate / 8, 1),
                   &opts.server, &sa, &opts.dhost, &opts.shost, &opts.bssid,
                   opts.tid, opts.issta);
    }
    else {
        run_server(sock, msock >= 0, &opts.server, NULL,
                   &opts.dhost, &opts.shost, &opts.bssid, !opts.issta);
    }

    /* Cleanup */
    if (usock >= 0) {
        close(usock);
    }
    if (msock >= 0) {
        close(msock);
    }
    timer_delete(timer);
    return 0;
}
