/*
 * Ciloipool++ - C++ Bitcoin pool server
 * Copyright (C) 2011-2013  Luke Dashjr <luke-jr+ciloipool++@utopios.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include "../tweaks.h"
#include "varlen.h"

unsigned _varlen_ignoredrc;

uint64_t varlenDecode(const bytes_t b, bytes_t &out_b, unsigned *rc) {
	if (b[0] == 0xff)
	{
		rc[0] += 9;
		out_b = bytes_t(b.begin() + 9, b.end());
		return unpack_LE_Q(&b[1]);
	}
	if (b[0] == 0xfe)
	{
		rc[0] += 5;
		out_b = bytes_t(b.begin() + 5, b.end());
		return unpack_LE_L(&b[1]);
	}
	if (b[0] == 0xfd)
	{
		rc[0] += 3;
		out_b = bytes_t(b.begin() + 3, b.end());
		return unpack_LE_H(&b[1]);
	}
	rc[0] += 1;
	out_b = bytes_t(b.begin() + 1, b.end());
	return b[0];
}

bytes_t varlenEncode(uint64_t n) {
	if (n < 0xfd)
		return bytes_t(1, n);
	bytes_t rv;
	if (n <= 0xffff)
	{
		rv.push_back('\xfd');
		pack_LE_H(rv, n);
		return rv;
	}
	if (n <= 0xffffffff)
	{
		rv.push_back('\xfe');
		pack_LE_L(rv, n);
		return rv;
	}
	rv.push_back('\xff');
	pack_LE_Q(rv, n);
	return rv;
}

// tests
INIT(test) {
	assert(BYTES(0) == varlenEncode(0));
	assert(BYTES(0xfc) == varlenEncode(0xfc));
	assert(BYTES(0xfd, 0xfd, 0) == varlenEncode(0xfd));
	assert(BYTES(0xfd, 0xff, 0xff) == varlenEncode(0xffff));
	assert(BYTES(0xfe, 0, 0, 1, 0) == varlenEncode(0x10000));
	assert(BYTES(0xfe, 0xff, 0xff, 0xff, 0xff) == varlenEncode(0xffffffff));
	assert(BYTES(0xff, 0, 0, 0, 0, 1, 0, 0, 0) == varlenEncode(0x100000000));
	assert(BYTES(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) == varlenEncode(0xffffffffffffffff));
}
