/*
 * AirTap: Capture IEEE 802.11 packets
 *
 * Dino Dai Zovi <ddz@theta44.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap.h>

#ifdef __FreeBSD__
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_radiotap.h>
#endif /* __FreeBSD__ */

#ifdef __Linux__
#include <linux/802_11.h>
#endif /* __Linux__ */

#include "airtap.h"

#define TO_MS 10

int init_pcap(char*);

/*
 * Datalink decoder table
 */
typedef void (*datalink_decoder)(const u_char*, at_frame_info_t*);

#ifdef __FreeBSD__
static void decode_ieee802_11_radio(const u_char*, at_frame_info_t*);
#endif /* __FreeBSD__ */

static void decode_prism_header(const u_char*, at_frame_info_t*);
static void decode_ieee802_11(const u_char*, at_frame_info_t*);

struct {
    int              datalink;
    datalink_decoder decoder;
} datalink_decoders[] = {
    /* Ordered by perference in case interface supports multiple */
#ifdef __FreeBSD__
    {DLT_IEEE802_11_RADIO, decode_ieee802_11_radio},
#endif /* __FreeBSD__ */
    {DLT_PRISM_HEADER, decode_prism_header},
    {DLT_IEEE802_11, decode_ieee802_11},
    //{DLT_AIRONET_HEADER, decode_aironet_header},
    //{DLT_IEEE802_11_RADIO_AVS, decode_ieee802_11_radio_avs},
    {-1, NULL}
};

static int does_file_exist(char* path)
{
    struct stat sb;

    return (stat(path, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFREG) ? 1 : 0;
}

static void handle_packet(u_char* u, const struct pcap_pkthdr* pkthdr,
                          const u_char* pkt)
{
    datalink_decoder decoder = (datalink_decoder)u;

    (*decoder)(pkt, NULL);
}

struct at_hook {
    struct at_hook* next;
    unsigned char   type;
    unsigned char   subtype;
    unsigned char   dir;
    at_hook_t       hook;
};

/* dir, type, subtype */
struct at_hook* hooks[4][16] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

void airtap_add_hook(unsigned int type, unsigned int subtype,
                     unsigned int dir, at_hook_t hook)
{
    struct at_hook** h;

    /*
     * Handle wild cards
     */
    
    for (h = &(hooks[type >> 2][subtype >> 4]); *h != NULL; h = &(*h)->next);

    if ((*h = malloc(sizeof(struct at_hook))) == NULL) {
        perror("airtap_add_hook: malloc");
        exit(EXIT_FAILURE);
    }
    
    (*h)->next = NULL;
    (*h)->type = type;
    (*h)->subtype = subtype;
    (*h)->dir = dir;
    (*h)->hook = hook;
}

static void call_hooks(unsigned int type,
                       unsigned int subtype,
                       unsigned int dir,
                       const u_char* frame,
                       const at_frame_info_t* frame_info)
{
    unsigned int t = type >> 2, s = subtype >> 4;
    struct at_hook* h;
    
    assert(t < 3 && s <= 15);

    /* Specific type/subtype handler */
    for (h = hooks[t][s]; h; h = h->next)
        if (h->dir == AT_DIR_ALL || h->dir == dir)
            (*h->hook)(frame, frame_info);
                
    /* All subtypes handler */
    for (h = hooks[3][t]; h; h = h->next)
        if (h->dir == AT_DIR_ALL || h->dir == dir)
            (*h->hook)(frame, frame_info);

    /* All types handler */
    for (h = hooks[3][4]; h; h = h->next)
        if (h->dir == AT_DIR_ALL || h->dir == dir)
            (*h->hook)(frame, frame_info);
}

static pcap_t* pcap = NULL;
static datalink_decoder decode_datalink = NULL;

int airtap_open(char* file_or_int)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int* datalinks, n_datalinks, i, j;
    
    /*
     * Read packets from pcap interface or file
     */
    
    if (does_file_exist(file_or_int)) {
        if (!(pcap = pcap_open_offline(file_or_int, pcap_errbuf))) {
            fprintf(stderr, "init_pcap: pcap_open_offline: %s\n", pcap_errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else {
        if (!(pcap = pcap_open_live(file_or_int,
                                    2500,    /* snaplen: whole packet */
                                    1,    /* promisc: yes */
                                    TO_MS,
                                    pcap_errbuf))) {
            fprintf(stderr, "init_pcap: pcap_open_live: %s\n", pcap_errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /*
     * Select best available datalink
     */
    
    if ((n_datalinks = pcap_list_datalinks(pcap, &datalinks)) < 0) {
        pcap_perror(pcap, "init_pcap: pcap_list_datalinks");
        exit(EXIT_FAILURE);
    }

    for (i = 0; !decode_datalink && datalink_decoders[i].datalink > 0; i++) {
        for (j = 0; j < n_datalinks; j++) {
            if (datalink_decoders[i].datalink == datalinks[j]) {
                if (pcap_set_datalink(pcap,
                                      datalink_decoders[i].datalink) < 0) {
                    pcap_perror(pcap, "init_pcap: pcap_set_datalink");
                    exit(EXIT_FAILURE);
                }
                
                decode_datalink = datalink_decoders[i].decoder;
            }
        }
    }

    if (!decode_datalink) {
        fprintf(stderr, "init_pcap: no suitable datalink decoder found\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
    
int airtap_loop()
{
    /*
     * Read packets forever
     */
    return pcap_loop(pcap, -1, handle_packet, (u_char*)decode_datalink);
}

#ifdef __FreeBSD__

/*********************************************************************
 *                   BSD Radiotap Datalink support                   *
 *********************************************************************/

/* Copied from FreeBSD header in notoriously bad style */
struct wi_rx_radiotap_header {
        struct ieee80211_radiotap_header wr_ihdr;
        u_int8_t        wr_flags;
        u_int8_t        wr_rate;
        u_int16_t       wr_chan_freq;
        u_int16_t       wr_chan_flags;
        u_int8_t        wr_antsignal;
        u_int8_t        wr_antnoise;
};

void
decode_ieee802_11_radio(const u_char* pkt, at_frame_info_t* frame_info)
{
    /*
     * XXX: We should really not hardcode static radiotap header types
     */
    struct wi_rx_radiotap_header* rt_hdr =
        (struct wi_rx_radiotap_header*)pkt;
    struct ieee80211_frame* frame =
        (struct ieee80211_frame*)
        (pkt + sizeof(struct wi_rx_radiotap_header));

    decode_ieee802_11((const u_char*)frame);
}
#endif /* __FreeBSD__ */

void
decode_prism_header(const u_char* pkt, at_frame_info_t* frame_info)
{
    struct at_prism_header* p2_hdr =
        (struct at_prism_header*)pkt;
    struct at_wifi_frame* frame =
        (struct at_wifi_frame*)
        (pkt + sizeof(struct at_prism_header));

    /*
     * XXX: Extract signal and noise and place in AirTap header
     */

    if (frame_info == NULL) {
        frame_info = (at_frame_info_t*)malloc(sizeof(at_frame_info_t));
    }

    frame_info->channel = p2_hdr->channel.data;
    frame_info->signal  = p2_hdr->signal.data;
    frame_info->noise   = p2_hdr->noise.data;
    
    decode_ieee802_11((const u_char*)frame, frame_info);
}

void
decode_ieee802_11(const u_char* pkt, at_frame_info_t* frame_info)
{
    struct at_wifi_frame* frame =
        (struct at_wifi_frame*)pkt;

    u_int8_t
        type = frame->frame_control & AT_TYPE_ALL,
        subtype = frame->frame_control & AT_SUBTYPE_ALL,
        direction = (frame->frame_control & (AT_DIR_ALL << 8)) >> 8;

    assert((frame->frame_control & 0x3) == 0);

    call_hooks(type, subtype, direction, (const u_char*)frame, frame_info);
}
