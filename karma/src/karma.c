/*
 * KARMA Attacks Radioed Machines Automatically
 *
 * Dino Dai Zovi <ddz@theta44.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>

#include "airtap.h"
#include "karma.h"

struct sta* sta_list = NULL;

static void dump_sta_info(sta_t* sta)
{
    struct ssid* s;
    
    fprintf(stderr, "STA 0x%.8x %d", sta->staid, sta->state);
    
    for (s = sta->probed_networks; s; s = s->next)
        fprintf(stderr, " %s(%d)", s->ssid, s->seq);

    fprintf(stderr, "\n");
}

void on_probe_req(const unsigned char* f, const at_frame_info_t* frame_info)
{
    struct at_wifi_frame* frame =
        (struct at_wifi_frame*)f;
    const char* body = (char*)f + sizeof(struct at_wifi_frame);

    char* ssid;
    unsigned int staid;
    u_int16_t seq;

    struct ssid** s;
    struct sta** sta_iter;
    struct sta* sta_entry = NULL;
    sta_t* sta = NULL;
    int do_update = 0;
    size_t ssid_len;
    
    /*
     * Probe request is:
     * SSID, Supported rates
     */

    assert(body[0] == 0);

    ssid_len = (size_t)body[1];
    
    if (ssid_len == 32) {    /* Garbage probe requests */
	ssid = strdup("<random>");
    }
    else if (ssid_len > 0) {
        ssid = malloc(ssid_len + 1);
        strncpy(ssid, &body[2], body[1]);
        ssid[ssid_len] = '\0';
    }
    else {
        ssid = strdup("<broadcast>");
    }

    /*
     * addr2 is STA address
     */

    memcpy(&seq, &frame->sequence_control, sizeof(seq));
    seq = (seq & 0xfff0) >> 4;
    
    staid =
        (frame->address2[2] << 24) |
        (frame->address2[3] << 16) |
        (frame->address2[4] << 8) |
        (frame->address2[5]);

    /*
     * Find station entry in list
     */
    for (sta_iter = &sta_list; *sta_iter; sta_iter = &((*sta_iter)->next)) {
        if (((*sta_iter)->sta)->staid == staid) {
            sta_entry = *sta_iter;
            *sta_iter = (*sta_iter)->next;
            break;
        }
    }

    /*
     * Allocate a new one if it wasn't found
     */
    if (!sta_entry) {
        sta_entry = malloc(sizeof(struct sta));
        sta_entry->sta = malloc(sizeof(sta_t));

        sta_entry->sta->staid = staid;
        memcpy(&(sta_entry->sta->mac), &(frame->address2), 6);
        
        sta_entry->sta->last_seq = sta_entry->sta->signal = 0;
        
        sta_entry->sta->state = UNKNOWN;
        sta_entry->sta->probed_networks = NULL;

        do_update = 1;
    }
    
    /*
     * Update station information
     */
    sta = sta_entry->sta;
    sta->last_seq = seq;
    if (frame_info) {
        sta->signal = frame_info->signal;
    }
    
    /*
     * Find SSID in this station's probed networks list and add it if
     * it wasn't found.
     */
    for (s = &(sta->probed_networks); *s; s = &(*s)->next) {
        if (strcmp((*s)->ssid, ssid) == 0) {
            /*
             * Move to front
             */
            struct ssid* s2 = *s;

            (*s) = (*s)->next;
            s2->next = sta->probed_networks;
            sta->probed_networks = s2;
            s = &(sta->probed_networks);
            
            break;
        }
    }

    if (*s == NULL) {
        struct ssid* s2;
        
        if ((s2 = malloc(sizeof(struct ssid))) == NULL) {
            perror("on_probe_req: malloc");
        }
        
        s2->next = sta->probed_networks;
        s2->ssid = strdup(ssid);
        s2->seq = seq;

        sta->probed_networks = s2;
        
        s = &(sta->probed_networks);

        do_update = 1;
    }
    else {
        (*s)->seq = seq;
    }

    /*
     * Put station entry back in list
     */
    sta_entry->next = sta_list;
    sta_list = sta_entry;
    
    free(ssid);
    
    /* dump_sta_info(sta); */

    /*
     * When there is no network around and a room full of laptops,
     * there is a Probe Request storm and we want to be conservative
     * about when we do screen updates.
     */
    
    /* if (do_update) */
        kui_update();
}

int main(int argc, char* argv[])
{
    airtap_open(argv[1]);
    
    /*
     * Install hooks
     */
    airtap_add_hook(AT_TYPE_MGMT,
                    AT_MGMT_SUBTYPE_PROBE_REQ,
                    AT_DIR_NODS,
                    on_probe_req);

    kui_init();
    
    /*
     * Deliver justice.
     */
    return airtap_loop();
}
