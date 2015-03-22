/*
 *     License: BSD/GPLv2
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef FRAME_PLUGIN_HEADER_H_
#define FRAME_PLUGIN_HEADER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/pcap.h"
#include "generic_plugin_header.h"

#define MAC_LEN 6
#define COPY_MAC(source, dest, counter)	if (source) { \
											(dest)[(counter) + 1] = (unsigned char *)malloc(sizeof(unsigned char *) * MAC_LEN); \
											memcpy((dest)[(counter)++], (source), sizeof(unsigned char) * MAC_LEN); \
										}
#define COPY_MAC_TO_ARRAY(src, dest) dest[0] = src[0]; dest[1] = src[1]; dest[2] = src[2]; dest[3] = src[3]; dest[4] = src[4]; dest[5] = src[5]
#define NULLIFY_MAC_ARRAY(array) (array)[0] = (array)[1] = (array)[2] = (array)[3] = (array)[4] = (array)[5] = 0
#define FRAME_TYPE_TO_STRING(type)	((type) == FRAME_TYPE_MANAGEMENT) ? "Management" : ((type) == FRAME_TYPE_CONTROL) ? "Control" : ((type) == FRAME_TYPE_DATA) ? "Data" : "Invalid"

#define ANALYZES_ALL_FRAMES		-1

#define NO_TIME_CONSTRAINT		-1

#define FRAME_TYPE_MANAGEMENT	0
#define FRAME_TYPE_CONTROL		1
#define FRAME_TYPE_DATA			2

DLL_EXPORT int static_frame_type();
DLL_EXPORT int static_frame_subtype();
DLL_EXPORT int need_all_frames();
DLL_EXPORT int is_single_frame_attack();
DLL_EXPORT int require_packet_parsed();

DLL_EXPORT int can_use_frame(struct pcap_packet * packet, void * config);
DLL_EXPORT int analyze(struct pcap_packet * packet, void * config);
DLL_EXPORT int nb_frames_before_analyzing(void * config);
DLL_EXPORT int time_ms_before_analyzing(void * config);
DLL_EXPORT int is_attacked(struct pcap_packet * packet_list, void * config);
DLL_EXPORT char * attack_details(void * config);

// nb_mac indicates the amount of mac in the returned array
// deauth indicates if the macs needs to be deauthenticated.
DLL_EXPORT unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth);
DLL_EXPORT void clear_attack(void * config); // Cleanup any data stored about the attack by the plugin

#ifdef __cplusplus
}
#endif

#endif /* FRAME_PLUGIN_HEADER_H_ */
