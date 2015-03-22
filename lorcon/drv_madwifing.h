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

#ifndef __DRV_MADWIFING_H__
#define __DRV_MADWIFING_H__

#include "config.h"
#include <lorcon.h>

#if defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS)

#define USE_DRV_MADWIFING		1

int drv_madwifing_init(lorcon_t *);
lorcon_driver_t *drv_madwifing_listdriver(lorcon_driver_t *);

#endif /* big test */

#endif

