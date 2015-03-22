/*
 * OpenWIPS-ng sensor.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */
#include <stdlib.h>
#include "structures.h"
#include "common/defines.h"

struct rpcap_link * init_new_rpcap_link()
{
	struct rpcap_link * ret = (struct rpcap_link *)malloc(sizeof(struct rpcap_link));
	ret->encrypted = -1;
	ret->compressed = -1;
	ret->pasv = -1;
	ret->port = -1;
	ret->host = NULL;
	ret->send_payload = -1;
	ret->send_data_frames = -1;

	return ret;
}

int free_rpcap_link(struct rpcap_link ** link)
{
	if (link == NULL || *link == NULL) {
		return EXIT_FAILURE;
	}

	FREE_AND_NULLIFY((*link)->host);
	FREE_AND_NULLIFY(*link);

	return EXIT_SUCCESS;
}
