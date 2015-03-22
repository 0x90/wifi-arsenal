/*
 * Reaver - Session save/restore functions
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

#ifndef SESSION_H
#define SESSION_H

#include <sys/types.h>
#include <sys/stat.h>
#include "defs.h"
#include "misc.h"
#include "globule.h"
#include "sql.h"
#include "config.h"

#ifndef CONF_DIR
#define CONF_DIR	"/etc/reaver"
#endif

#define MAX_LINE_SIZE	128
#define CONF_EXT	"wpc"

#define P1_STR_LEN	4
#define P2_STR_LEN      3
#define P1_READ_LEN     (P1_STR_LEN + 2)        /* Read lengths == (strlen + new line + null byte) */
#define P2_READ_LEN     (P2_STR_LEN + 2)

int restore_session();
int save_session();
int configuration_directory_exists();

#endif
