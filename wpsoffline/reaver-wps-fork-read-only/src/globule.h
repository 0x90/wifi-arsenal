/*
 * Reaver - Global variable access functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef GLOBULE_H
#define GLOBULE_H

#include "defs.h"

struct globals
{
    int last_wps_state;             /* Holds the previous WPS state as stored in wps->state */

    int p1_index;                   /* Index into p1 array for building WPS pins */

    int p2_index;                   /* Index into p2 array for building WPS pins */

    char *p1[P1_SIZE];              /* Array of all possible values for the firt half of the pin */

    char *p2[P2_SIZE];              /* Array of all possible values for the second half of the pin */

    char *static_p1;		/* Static P1, as supplied by the user */

    char *static_p2;		/* Static P2, as supplied by the user */

    enum key_state key_status;      /* Indicates the status of the key cracking: KEY1_WIP | KEY2_WIP | KEY_DONE */

    int dh_small;			/* Use small DH keys to improve WPS speed */

    int external_association;	/* Use an external application to perform AP association  */

    int oo_send_nack;		/* Set to 1 to send WSC_NACK when an out of order packet is received */

    int win7_compat;		/* Set to 1 to make WPS messages mimic Windows 7 settings. */

    int exhaustive;		/* Set to 1 to use exhaustive pin generation instead of checksum the last digit */

    int delay;                      /* Seconds to sleep in between key attempts */

    int fail_delay;                 /* Seconds to sleep after WARN_FAILURE_COUNT WPS exchange failures */

    int recurring_delay;            /* Sleep recurring_delay seconds for every recurring_delay_count attempts */

    int lock_delay;			/* Sleep lock_delay seconds when wpscrack detects that the AP has locked WPS pin attempts */

    int ignore_locks;		/* Ignore locked state */

    int recurring_delay_count;	/* Enter a recurring delay after recurring_delay_count pin attempts */

    int eap_terminate;              /* Experimental */

    int max_pin_attempts;           /* Maximum number of pin attempts */

    int rx_timeout;                 /* Receive timeout period (seconds) */

    int timeout_is_nack;            /* Treat M5/M7 receive timeouts as NACKs (only needed for shoddy WPS implementations) */

    int m57_timeout;                /* Timeout period for receiving an M5/M7 response (uSeconds) */

    int out_of_time;                /* Set to 1 when sigalrm sounds */

    enum debug_level debug;         /* Current debug level: INFO | CRITICAL | WARNING | VERBOSE */

    int eapol_start_count;          /* Tracks how many times in a row we've attempted to start and EAP session */

    int fixed_channel;              /* Disables channel hopping if set */

    int auto_channel_select;	/* Diables automatic parsing and changing of the current channel number, as specified in the AP's beacon packet */

    int auto_detect_options;	/* If true, Reaver will auto detect the best command line options for the attack */

    int wifi_band;			/* Determines if we use the A/N bands or B/G bands */

    int channel;			/* Holds the current channel number */

    int max_num_probes;		/* Maximum number of probe requests to send to an AP during survey mode */

    int validate_fcs;		/* If 1, validate each packet's FCS. If 0, process packets even with invalid FCS. */

    enum wsc_op_code opcode;        /* WFA opcode, received by exchange.c and used by builder.c */

    uint8_t eap_id;                 /* Tracks the EAP ID value for building EAP repsonse headers */

    uint16_t ap_capability;         /* Capability information of the target AP as specified in the AP's beacon packets */

    unsigned char bssid[MAC_ADDR_LEN];      /* Target BSSID */

    unsigned char mac[MAC_ADDR_LEN];                /* Source MAC address */

    unsigned char *ap_rates;	/* Supported rates IE data, as reported by the AP */

    int ap_rates_len;		/* Length of the supported rates IE data */

    FILE *fp;			/* Handle to log file */

    char *session;			/* Path to session file */

    char *ssid;                     /* Target SSID */

    char *iface;                    /* Interface name */

    char *pin;                      /* Pointer to the recovered WPS pin value */

    char *exec_string;		/* Pointer to user-supplied command to execute upon success */

    enum nack_code nack_reason;     /* Stores the nack code for the last received WSC_NACK message */

    pcap_t *handle;                 /* Pcap handle */

    struct wps_data *wps;           /* 
                                     * wpa_supplicant's wps_data structure, needed for almost all wpa_supplicant
                                     * function calls.
                                     */
} *globule;

int globule_init();
void globule_deinit();
void set_log_file(FILE *fp);
FILE *get_log_file(void);
void set_last_wps_state(int state);
int get_last_wps_state();
void set_session(char *value);   
char *get_session();
void set_p1_index(int index);
int get_p1_index();
void set_p2_index(int index);
int get_p2_index();
void set_p1(int index, char *value);
char *get_p1(int index);
void set_p2(int index, char *value);
char *get_p2(int index);
void set_key_status(enum key_state status);
enum key_state get_key_status();
void set_delay(int delay);
int get_delay();
void set_fail_delay(int delay);
int get_fail_delay();
void set_validate_fcs(int validate);
int get_validate_fcs(void);
void set_recurring_delay(int delay);
int get_recurring_delay();
void set_recurring_delay_count(int value);
int get_recurring_delay_count();
void set_lock_delay(int value);
int get_lock_delay();
void set_ignore_locks(int value);
int get_ignore_locks();
void set_eap_terminate(int value);
int get_eap_terminate();
void set_max_pin_attempts(int value);
int get_max_pin_attempts();
int get_max_num_probes();
void set_max_num_probes(int value);
void set_rx_timeout(int value);
int get_rx_timeout();
void set_timeout_is_nack(int value);
int get_timeout_is_nack();
void set_m57_timeout(int value);
int get_m57_timeout();
void set_out_of_time(int value);
int get_out_of_time();
void set_debug(enum debug_level value);
enum debug_level get_debug();
void set_eapol_start_count(int value);
int get_eapol_start_count();
void set_fixed_channel(int value);
int get_fixed_channel();
void set_auto_channel_select(int value);
int get_auto_channel_select();
void set_auto_detect_options(int value);
int get_auto_detect_options();
void set_wifi_band(int value);
int get_wifi_band();
void set_opcode(enum wsc_op_code value);
enum wsc_op_code get_opcode();
void set_eap_id(uint8_t value);
uint8_t get_eap_id();
void set_ap_capability(uint16_t value);
uint16_t get_ap_capability();
void set_bssid(unsigned char *value);
unsigned char *get_bssid();
void set_mac(unsigned char *value);
unsigned char *get_mac();
void set_channel(int channel);
int get_channel(void);
void set_ssid(char *value);
char *get_ssid();
void set_iface(char *value);
char *get_iface();
void set_pin(char *value);
char *get_pin();
void set_static_p1(char *value);
char *get_static_p1(void);
void set_static_p2(char *value);
char *get_static_p2(void);
void set_win7_compat(int value);
int get_win7_compat(void);
void set_exhaustive(int value);
int get_exhaustive(void);
void set_dh_small(int value);
int get_dh_small(void);
void set_external_association(int value);
int get_external_association(void);
void set_nack_reason(enum nack_code value);
enum nack_code get_nack_reason();
void set_handle(pcap_t *value);
pcap_t *get_handle();
void set_wps(struct wps_data *value);
struct wps_data *get_wps();
void set_ap_rates(unsigned char *value, int len);
unsigned char *get_ap_rates(int *len);
void set_exec_string(char *string);
char *get_exec_string(void);
void set_oo_send_nack(int value);
int get_oo_send_nack(void);

#endif
