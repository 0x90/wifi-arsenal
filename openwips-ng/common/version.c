/*
 * OpenWIPS-ng - common stuff.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "version.h"


/* Return the version number */
char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc)
{
#define PROVIS_LEN 20
	int len;
	char * temp;
	char * provis = calloc(1, PROVIS_LEN * sizeof(char));
	len = strlen(progname) + 201;
	temp = (char *) calloc(1,len * sizeof(char));

	snprintf(temp, len, "%s v%d.%d", progname, maj, min);

	if (submin > 0) {
		snprintf(provis, PROVIS_LEN,".%d",submin);
		strncat(temp, provis, len - strlen(temp));
		memset(provis,0,PROVIS_LEN);
	}

	if (rc > 0) {
		snprintf(provis, PROVIS_LEN, " rc%d", rc);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, PROVIS_LEN);
	} else if (beta > 0) {
		snprintf(provis, PROVIS_LEN, " beta%d", beta);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, PROVIS_LEN);
	}

	if (svnrev > 0) {
		snprintf(provis, PROVIS_LEN," r%d",svnrev);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, PROVIS_LEN);
	}

	free(provis);
	temp = realloc(temp, strlen(temp)+1);
	return temp;
#undef PROVIS_LEN
}
