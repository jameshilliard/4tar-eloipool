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

#include <cstddef>
#include <string>
#include "tweaks.h"

// libblkmaker private, should be replaced...
extern "C" {
	extern bool _blkmk_b58tobin(void *bin, size_t binsz, const char *b58, size_t b58sz);
	extern int _blkmk_b58check(void *bin, size_t binsz, const char *b58);
}

bytes_t b58decode(std::string b58, size_t expectedlen) {
	char buf[expectedlen];
	if (!_blkmk_b58tobin(buf, expectedlen, b58.c_str(), 0))
		throw AssertionError();
	if (_blkmk_b58check(buf, expectedlen, b58.c_str()) < 0)
		throw AssertionError();
	return bytes_t(&buf[0], &buf[expectedlen]);
}
