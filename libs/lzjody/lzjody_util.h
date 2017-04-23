/*
 * Lempel-Ziv-JodyBruchon compression library
 *
 * Copyright (C) 2014, 2015 by Jody Bruchon <jody@jodybruchon.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LZJODY_UTIL_H
#define LZJODY_UTIL_H

#include <lzjody.h>

#define LZJODY_UTIL_VER "0.1"
#define LZJODY_UTIL_VERDATE "2014-12-29"

/* Debugging stuff */
#ifndef DLOG
 #ifdef DEBUG
  #define DLOG(...) fprintf(stderr, __VA_ARGS__)
 #else
  #define DLOG(...)
 #endif
#endif

/* Use POSIX threads in compression utility  (define this in Makefile) */
/* #define THREADED 1 */

struct files_t {
	FILE *in;
	FILE *out;
};

/* Number of LZJODY_BSIZE blocks to process per thread */
#define CHUNK 1024

#ifdef THREADED
/* Per-thread working state */
struct thread_info {
	unsigned char blk[LZJODY_BSIZE * CHUNK];	/* Thread input blocks */
	unsigned char out[(LZJODY_BSIZE + 4) * CHUNK];	/* Thread output blocks */
	char options;	/* Compressor options */
	pthread_t id;	/* Thread ID */
	int block;	/* What block is thread working on? */
	int length;	/* Total bytes in block */
	int o_length;	/* Output length */
	int working;	/* Is thread working (1) or idle (0)? */
};
#endif /* THREADED */

#endif	/* LZJODY_UTIL_H */
