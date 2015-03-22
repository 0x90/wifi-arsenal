/*
    This file is part of lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

/*
 * LORCON packet assembly system
 *
 * Relatively naive system for assembling packets from a list of components
 * which are then frozen into a uint8_t array for injection.
 *
 * Packet components may be named.  No enforcement of name duplication
 * is made.
 *
 * Basic manipulation functions are provided for assembling packet
 * content.
 *
 */

#ifndef __PACKET_ASSEMBLY_H__
#define __PACKET_ASSEMBLY_H__

/*
 * Basically a big linked list which gets frozen into a static
 * uint8_t for transmission.
 *
 * Functions are included for searching and replacing components, freezing
 * the list to a uint8, and freeing the structures
 *
 */

struct lcpa_metapack {
	/* Linked list */
	struct lcpa_metapack *prev;
	struct lcpa_metapack *next;

	/* String name for this packet component */
	char type[24];

	/* Length of the chunk */
	int len;

	/* Pointer to chunk of data */
	uint8_t *data;

	/* Do we free this data when we free the list, or is it controlled
	 * by the user application? */
	int freedata;
};
typedef struct lcpa_metapack lcpa_metapack_t;

/* Initialize a packet list */
struct lcpa_metapack *lcpa_init();

/* Append a copied data item to a list.  This copied data will be freed when
 * the list is freed, and the caller can destroy the original data in the meantime.
 * in_pack may be any component of the list, the new element will be appended
 * to the end of the list.
 *
 * The new component is returned.
 */
struct lcpa_metapack *lcpa_append_copy(struct lcpa_metapack *in_pack, char *in_type, 
									   int in_len, uint8_t *in_data);

/* Append a data item to a list.  This is NOT copied, will NOT be freed when
 * the list is freed, and the caller MUST NOT destroy the data until the list
 * is destroyed.
 * in_pack may be any component of the list, the new element will be appended
 * to the end of the list.
 *
 * The new component is returned.
 */
struct lcpa_metapack *lcpa_append(struct lcpa_metapack *in_pack, char *in_type,
								  int in_len, uint8_t *in_data);

/* Insert a component into the packet.  This copied data will be freed when the list
 * is freed, and the caller may destroy the original data at will.
 * in_pack may be any component of the list.  Data will be inserted after
 * the component and the remainder of the list will be shuffled to make
 * room.
 *
 * The new component is returned.
 */
struct lcpa_metapack *lcpa_insert_copy(struct lcpa_metapack *in_pack, char *in_type,
									   int in_len, uint8_t *in_data);

/* Insert a component into the packet.  This data is NOT copied and will NOT
 * be freed when the packet list is freed.  The caller MUST NOT destroy this data
 * until the list is freed.
 *
 * The component is added after the component provided in in_pack.
 *
 * The new component is returned.
 */
struct lcpa_metapack *lcpa_insert(struct lcpa_metapack *in_pack, char *in_type,
								  int in_len, uint8_t *in_data);

/* Find a component by name.  Can be used for iterative searching by passing
 * a non-head component as the start position
 *
 * If no value is found, NULL is returned
 */
struct lcpa_metapack *lcpa_find_name(struct lcpa_metapack *in_head, char *in_type);

/* Replace a component in the packet.  The data is copied and will be freed when the
 * packet list is freed.  If the packet being replaced contains copied data, it 
 * will be freed.
 *
 * All pointers to the component remain valid, however any pointers to the
 * component data must be treated as invalid if the original component data 
 * was copied.
 */
void lcpa_replace_copy(struct lcpa_metapack *in_pack, char *in_type, 
					   int in_len, uint8_t *in_data);

/* Replace a component in the packet.  The data is NOT copied and will NOT be freed
 * when the packet list is freed.  The caller MUST NOT destroy the data before the
 * packet list is freed.
 *
 * All pointers to the component remain valid, however any pointers to the
 * component data bust me treated as invalid if the original component data
 * was copied
 */
void lcpa_replace(struct lcpa_metapack *in_pack, char *in_type,
				  int in_len, uint8_t *in_data);

/* Free a metapacket list.  
 *
 * Any element of the list may be passed as in_head, however the entire list
 * will be removed.
 *
 * No element of the list (including in_head) will be valid and all external
 * reference to them must be treated as freed memory.
 *
 * For a list to be re-used after lcpa_free(), it must be initialized anew with
 * lcpa_init().
 */
void lcpa_free(struct lcpa_metapack *in_head);

/* Get the size of an assembled LCPA packet */
int lcpa_size(struct lcpa_metapack *in_head);

/* Freeze a LCPA fragment packet into a bytestream.  The caller is responsible
 * for providing a bytestream of sufficient length. */
void lcpa_freeze(struct lcpa_metapack *in_head, u_char *bytes);

#endif

