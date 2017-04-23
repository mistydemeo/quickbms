/*
 * Byte plane transformation
 *
 * This code performs an n-plane transformation on a block of data.
 * For example, a 4-plane transform on "1200120112021023" would change
 * that string into "1111222200000123", a string which is easily
 * compressible, unlike the original. The resulting string has three
 * RLE runs and one incremental sequence.
 * Passing a negative num_planes reverses the transformation.
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

extern int byteplane_transform(const unsigned char * const in,
		unsigned char * const out, int length,
		char num_planes)
{
	int i;
	int plane = 0;
	int opos = 0;

	if (num_planes > 1) {
		/* Split 'in' to byteplanes, placing result in 'out' */
		while (plane < num_planes) {
			i = plane;
			while (i < length) {
				*(out + opos) = *(in + i);
				opos++;
				i += num_planes;
			}
			plane++;
		}
	} else if (num_planes > -1) return -1;
	else {
		num_planes = -num_planes;
		while (plane < num_planes) {
			i = plane;
			while (i < length) {
				*(out + i) = *(in + opos);
				opos++;
				i += num_planes;
			}
			plane++;
		}

	}
	if (opos != length) return -1;
	return 0;

}
