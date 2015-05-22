/*
 * asleap - actively recover weak LEAP passwords.  Pronounced "asleep".
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: apeek.h,v 1.3 2004/04/13 02:57:21 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* prototypes */
int find_pktsdelim(FILE *fp);
int test_filetype(char *filename);
int get_pcapdatalink(char *filename);
