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

#include "globule.h"

int globule_init()
{
    int ret = 0;

    globule = malloc(sizeof(struct globals));
    if(globule)
    {
        memset(globule, 0, sizeof(struct globals));
        ret = 1;
    }

    return ret;
}
void globule_deinit()
{
    int i = 0;

    if(globule)
    {
        for(i=0; i<P1_SIZE; i++)
        {
            if(globule->p1[i]) free(globule->p1[i]);
        }
        for(i=0; i<P2_SIZE; i++)
        {
            if(globule->p2[i]) free(globule->p2[i]);
        }

        if(globule->wps) wps_deinit(globule->wps);
        if(globule->handle) pcap_close(globule->handle);
        if(globule->pin) free(globule->pin);
        if(globule->iface) free(globule->iface);
        if(globule->ssid) free(globule->ssid);
        if(globule->session) free(globule->session);
        if(globule->static_p1) free(globule->static_p1);
        if(globule->static_p2) free(globule->static_p2);
        if(globule->fp) fclose(globule->fp);
        if(globule->exec_string) free(globule->exec_string);

        free(globule);
    }
}

void set_log_file(FILE *fp)
{
    globule->fp = fp;
}
FILE *get_log_file(void)
{
    return globule->fp;
}

void set_last_wps_state(int state)
{
    globule->last_wps_state = state;
}
int get_last_wps_state()
{
    return globule->last_wps_state;
}

void set_session(char *value)  
{ 
    globule->session = strdup(value);     
}
char *get_session()    
{
    return globule->session;  
} 

void set_p1_index(int index)
{
    if(index < P1_SIZE)
    {
        cprintf(VERBOSE,"[+] p1_index set to %i\n",index);
        globule->p1_index = index;
    }
}
int get_p1_index()
{
    return globule->p1_index;
}

void set_p2_index(int index)
{
    if(index <= P2_SIZE + globule->exhaustive*(P1_SIZE - P2_SIZE))
    {
        cprintf(VERBOSE,"[+] p2_index set to %i\n",index);
        globule->p2_index = index;
    }
}
int get_p2_index()
{
    return globule->p2_index;
}

void set_p1(int index, char *value)
{
    if(index < P1_SIZE)
    {
        globule->p1[index] = strdup(value);
    }
}
char *get_p1(int index)
{
    if(index < P1_SIZE)
    {
        return globule->p1[index];
    }
    return NULL;
}

void set_p2(int index, char *value)
{
    if(index < P2_SIZE)
    {
        globule->p2[index] = strdup(value);
    }
}
char *get_p2(int index)
{
    if(index < P2_SIZE)
    {
        return globule->p2[index];
    }
    return NULL;
}

void set_key_status(enum key_state status)
{
    globule->key_status = status;
}
enum key_state get_key_status()
{
    return globule->key_status;
}

void set_delay(int delay)
{
    globule->delay = delay;
}
int get_delay()
{
    return globule->delay;
}

void set_fail_delay(int delay)
{
    globule->fail_delay = delay;
}
int get_fail_delay()
{
    return globule->fail_delay;
}

void set_validate_fcs(int validate)
{
    globule->validate_fcs = validate;
}
int get_validate_fcs(void)
{
    return globule->validate_fcs;
}

void set_recurring_delay(int delay)
{
    globule->recurring_delay = delay;
}
int get_recurring_delay()
{
    return globule->recurring_delay;
}

void set_recurring_delay_count(int value)
{
    globule->recurring_delay_count = value;
}
int get_recurring_delay_count()
{
    return globule->recurring_delay_count;
}

void set_lock_delay(int value)
{
    globule->lock_delay = value;
}
int get_lock_delay()
{
    return globule->lock_delay;
}

void set_ignore_locks(int value)
{
    globule->ignore_locks = value;
}
int get_ignore_locks()
{
    return globule->ignore_locks;
}

void set_eap_terminate(int value)
{
    globule->eap_terminate = value;
}
int get_eap_terminate()
{
    return globule->eap_terminate;
}

void set_max_pin_attempts(int value)
{
    globule->max_pin_attempts = value;
}
int get_max_pin_attempts()
{
    return globule->max_pin_attempts;
}

void set_max_num_probes(int value)
{
    globule->max_num_probes = value;
}
int get_max_num_probes()
{
    return globule->max_num_probes;
}

void set_rx_timeout(int value)
{
    globule->rx_timeout = value;
}
int get_rx_timeout()
{
    return globule->rx_timeout;
}

void set_timeout_is_nack(int value)
{
    globule->timeout_is_nack = value;
}
int get_timeout_is_nack()
{
    return globule->timeout_is_nack;
}

void set_m57_timeout(int value)
{
    globule->m57_timeout = value;
}
int get_m57_timeout()
{
    return globule->m57_timeout;
}

void set_out_of_time(int value)
{
    globule->out_of_time = value;
}
int get_out_of_time()
{
    return globule->out_of_time;
}

void set_debug(enum debug_level value)
{
    globule->debug = value;
}
enum debug_level get_debug()
{
    return globule->debug;
}

void set_eapol_start_count(int value)
{
    globule->eapol_start_count = value;
}
int get_eapol_start_count()
{
    return globule->eapol_start_count;
}

void set_fixed_channel(int value)
{
    globule->fixed_channel = value;
}
int get_fixed_channel()
{
    return globule->fixed_channel;
}

void set_auto_channel_select(int value)
{
    globule->auto_channel_select = value;
}
int get_auto_channel_select()
{
    return globule->auto_channel_select;
}

void set_auto_detect_options(int value)
{
    globule->auto_detect_options = value;
}
int get_auto_detect_options()
{
    return globule->auto_detect_options;
}

void set_wifi_band(int value)
{
    globule->wifi_band = value;
}
int get_wifi_band()
{
    return globule->wifi_band;
}

void set_opcode(enum wsc_op_code value)
{
    globule->opcode = value;
}
enum wsc_op_code get_opcode()
{
    return globule->opcode;
}

void set_eap_id(uint8_t value)
{
    globule->eap_id = value;
}
uint8_t get_eap_id()
{
    return globule->eap_id;
}

void set_ap_capability(uint16_t value)
{
    globule->ap_capability = value;
}
uint16_t get_ap_capability()
{
    return globule->ap_capability;
}

void set_channel(int channel)
{
    globule->channel = channel;
}
int get_channel(void)
{
    return globule->channel;
}

void set_bssid(unsigned char *value)
{
    memcpy((unsigned char *) &globule->bssid, value, MAC_ADDR_LEN);
}
unsigned char *get_bssid()
{
    return (unsigned char *) &globule->bssid;
}

void set_mac(unsigned char *value)
{
    memcpy((unsigned char *) &globule->mac, value, MAC_ADDR_LEN);
}
unsigned char *get_mac()
{
    return (unsigned char *) &globule->mac;
}

void set_ssid(char *value)
{
    if(globule->ssid)
    {
        free(globule->ssid);
        globule->ssid = NULL;
    }

    if(value)
    {
        if(strlen(value) > 0)
        {
            globule->ssid = strdup(value);
        }
    }
}
char *get_ssid()
{
    return globule->ssid;
}

void set_iface(char *value)
{
    if(value)
    {
        if(globule->iface)
        {
            free(globule->iface);
        }

        globule->iface = strdup(value);
    }
    else if(globule->iface)
    {
        free(globule->iface);
        globule->iface = NULL;
    }
}
char *get_iface()
{
    return globule->iface;
}

void set_pin(char *value)
{
    globule->pin = strdup(value);
}
char *get_pin()
{
    return globule->pin;
}

void set_static_p1(char *value)
{
    globule->static_p1 = strdup(value);
}

char *get_static_p1(void)
{
    return globule->static_p1;
}

void set_static_p2(char *value)
{
    globule->static_p2 = strdup(value);
}

char *get_static_p2(void)
{
    return globule->static_p2;
}

void set_win7_compat(int value)
{
    globule->win7_compat = value;
}

int get_win7_compat(void)
{
    return globule->win7_compat;
}

void set_exhaustive(int value)
{
    globule->exhaustive = value;
    if(value == 1)
    {
        globule->max_pin_attempts=P1_SIZE+P1_SIZE;
    }
}

int get_exhaustive(void)
{
    return globule->exhaustive;
}

void set_dh_small(int value)
{
    globule->dh_small = value;
}
int get_dh_small(void)
{
    return globule->dh_small;
}

void set_external_association(int value)
{
    globule->external_association = value;
}
int get_external_association(void)
{
    return globule->external_association;
}

void set_nack_reason(enum nack_code value)
{
    globule->nack_reason = value;
}
enum nack_code get_nack_reason()
{
    return globule->nack_reason;
}

void set_handle(pcap_t *value)
{
    globule->handle = value;
}
pcap_t *get_handle()
{
    return globule->handle;
}

void set_wps(struct wps_data *value)
{
    globule->wps = value;
}
struct wps_data *get_wps()
{
    return globule->wps;
}

void set_ap_rates(unsigned char *value, int len)
{
    if(globule->ap_rates)
    {
        free(globule->ap_rates);
        globule->ap_rates = NULL;
        globule->ap_rates_len = 0;
    }

    globule->ap_rates = malloc(len);
    if(globule->ap_rates)
    {
        memcpy(globule->ap_rates, value, len);
        globule->ap_rates_len = len;
    }
}

unsigned char *get_ap_rates(int *len)
{
    *len = globule->ap_rates_len;
    return globule->ap_rates;
}

void set_exec_string(char *string)
{
    if(globule->exec_string)
    {
        free(globule->exec_string);
        globule->exec_string = NULL;
    }

    if(string)
    {
        globule->exec_string = strdup(string);
    }
}
char *get_exec_string(void)
{
    return globule->exec_string;
}

void set_oo_send_nack(int value)
{
    globule->oo_send_nack = value;
}
int get_oo_send_nack(void)
{
    return globule->oo_send_nack;
}
