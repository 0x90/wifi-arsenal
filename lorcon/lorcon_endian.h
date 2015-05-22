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

#ifndef __LORCON_ENDIAN_H__
#define __LORCON_ENDIAN_H__

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Generic endian flopping macros */
#ifdef WORDS_BIGENDIAN

#define lorcon_hton16(x) (x)
#define lorcon_ntoh16(x) (x)
#define lorcon_be16(x)	  (x)
#define lorcon_le16(x)	  lorcon_swap16((x))

#define lorcon_hton32(x) (x)
#define lorcon_ntoh32(x) (x)
#define lorcon_be32(x)	  (x)
#define lorcon_le32(x)	  lorcon_swap32((x))

#define lorcon_hton64(x) (x)
#define lorcon_ntoh64(x) (x)
#define lorcon_be64(x)	  (x)
#define lorcon_le64(x)	  lorcon_swap64((x))

#else

#define lorcon_hton16(x) lorcon_swap16((x))
#define lorcon_ntoh16(x) lorcon_swap16((x))
#define lorcon_le16(x)	  (x)
#define lorcon_be16(x)	  lorcon_swap16((x))

#define lorcon_hton32(x) lorcon_swap32((x))
#define lorcon_ntoh32(x) lorcon_swap32((x))
#define lorcon_le32(x)	  (x)
#define lorcon_be32(x)	  lorcon_swap32((x))

#define lorcon_hton64(x) lorcon_swap64((x))
#define lorcon_ntoh64(x) lorcon_swap64((x))
#define lorcon_le64(x)	  (x)
#define lorcon_be64(x)	  lorcon_swap64((x))

#endif

/* Swap magic */
#ifdef _MSC_VER

#define lorcon_swap16(x) (uint16_t)( \
		(((uint16_t)(x) & 0x00ff) << 8) | (((uint16_t)(x) & 0xff00) >> 8))

#define lorcon_swap32(x) (uint32_t)( \
        (((uint32_t)(x) & (uint32_t)0x000000ff) << 24) | \
        (((uint32_t)(x) & (uint32_t)0x0000ff00) << 8) | \
        (((uint32_t)(x) & (uint32_t)0x00ff0000) >> 8) | \
        (((uint32_t)(x) & (uint32_t)0xff000000) >> 24) )

#define lorcon_swap64(x) (uint64_t)( \
        (((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
        (((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56) )
#else

#define lorcon_swap16(x) \
({ \
    uint16_t __x = (x); \
    ((uint16_t)( \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0x00ff) << 8) | \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0xff00) >> 8) )); \
})

#define lorcon_swap32(x) \
({ \
    uint32_t __x = (x); \
    ((uint32_t)( \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x000000ff) << 24) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x0000ff00) << 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x00ff0000) >> 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0xff000000) >> 24) )); \
})

#define lorcon_swap64(x) \
({ \
    uint64_t __x = (x); \
    ((uint64_t)( \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

#endif

#endif
