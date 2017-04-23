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

#ifndef LZJODY_H
#define LZJODY_H

#ifdef __cplusplus
extern "C" {
#endif

#define LZJODY_VER "0.1"
#define LZJODY_VERDATE "2014-12-29"

/* Maximum amount of data the algorithm can process at a time */
#define LZJODY_BSIZE 4096

/* Options for the compressor */
#define O_FAST_LZ 0x01	/* Stop at first LZ match (faster but not recommended) */
#define O_NOPREFIX 0x40	/* Don't prefix lzjody_compress() data with the compressed length */
#define O_REALFLUSH 0x80	/* Make lzjody_flush_literals() flush without question */

/* Decompressor options (some copied from data block header) */
#define O_NOCOMPRESS 0x80	/* Incompressible block packing flag */

extern int lzjody_compress(const unsigned char * const, unsigned char * const,
		const unsigned int, const unsigned int);
extern int lzjody_decompress(const unsigned char * const, unsigned char * const,
		const unsigned int, const unsigned int);

#ifdef __cplusplus
}
#endif

#endif	/* LZJODY_H */
