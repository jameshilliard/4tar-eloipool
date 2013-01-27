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
#include <stdlib.h>
#include <string>
#include "../tweaks.h"
#include "script.h"
using namespace bitcoin::script;

#include "../base58.h"  // b58decode
#include "../util.h"  // dblsha

namespace bitcoin {
	namespace script {

static bytes_t _Address2PKH(std::string addr_s, uint32_t & ver) {
	bytes_t addr;
	try
	{
		addr = b58decode(addr_s, 25);
	}
	catch(...) {
		return bytes_t();
	}
	if (addr.empty())
		return bytes_t();
	ver = addr[0];
	bytes_t cksumA(addr.end() - 4, addr.end());
	bytes_t cksumB = dblsha(bytes_t(addr.begin(), addr.end() - 4));
	cksumB.erase(cksumB.begin() + 3);
	if (cksumA != cksumB)
		return bytes_t();
	return bytes_t(addr.begin() + 1, addr.end() - 4);
}

bytes_t BitcoinScript::toAddress(std::string addr) {
	uint32_t ver;
	bytes_t pubkeyhash = _Address2PKH(addr, ver);
	if (pubkeyhash.empty())
		throw ValueError{"invalid address"};
	bytes_t rv{0x76, 0xa9, 0x14};
	BYTES_APPEND(rv, pubkeyhash);
	BYTES_APPEND(rv, BYTES(0x88, 0xac));
	return rv;
}

unsigned countSigOps(bytes_t s) {
	// FIXME: don't count data as ops
	unsigned c = 0;
	for (bytes_t::iterator it = s.begin(); it != s.end(); ++it)
	{
		uint8_t ch = *it;
		if (0xac == ch & 0xfe)
			c += 1;
		else
		if (0xae == ch & 0xfe)
			c += 20;
	}
	return c;
}

// NOTE: This does not work for signed numbers (set the high bit) or zero (use BYTES(0))
bytes_t encodeUNum(uintmax_t n) {
	bytes_t s = BYTES(1);
	while (n > 127)
	{
		s[0] += 1;
		s.push_back(n % 256);
		n /= 256;
	}
	s.push_back(n);
	return s;
}

// encodeNum is a template in script.h

// tests
INIT(test) {
	assert(BYTES(0) == encodeNum(0));
	assert(BYTES(1, 0x55) == encodeNum(0x55));
	assert(BYTES(2, 0xfd, 0) == encodeNum(0xfd));
	assert(BYTES(3, 0xff, 0xff, 0) == encodeNum(0xffff));
	assert(BYTES(3, 0, 0, 1) == encodeNum(0x10000));
	assert(BYTES(5, 0xff, 0xff, 0xff, 0xff, 0) == encodeNum(0xffffffff));
}

	};
};

int main() {}