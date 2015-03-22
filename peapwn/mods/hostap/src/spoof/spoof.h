#ifndef SPOOF_H
#define SPOOF_H

#include "ap/hostapd.h"

struct spoof_ssid;
struct ieee802_11_elems;

u8 compound_mac_spoof[20];

typedef enum spoof_net_type { OPEN, DOT1X, WPA2 } spoof_net_type;

void set_spoofed_ssid(struct hostapd_data *hapd, struct spoof_ssid* spoofedssid, struct ieee802_11_elems* elems);

void spoof_write_challenge_sock(const u8* challenge, int challenge_len);
void spoof_read_response_sock(u8** response);

void spoof_cycle_ie(struct hostapd_data *hapd);

void spoof_cycle_store_ssid(struct hostapd_data *hapd, struct spoof_ssid* to_store);
struct spoof_ssid* spoof_cycle_ssid(struct hostapd_data *hapd);

#endif /* SPOOF_H */
