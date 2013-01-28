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

#include <iostream>
#include <tuple>
#include "tweaks.h"
#include "util.h"

#include <gcrypt.h>
#include <math.h>  // log
#if 0
import re
import string
from struct import unpack
import traceback

def YN(b):
	if b is None:
		return None
	return 'Y' if b else 'N'

def _maybe_int(n):
	n_int = int(n)
	if n == n_int:
		return n_int
	return n

def target2pdiff(target):
	if target is None:
		return None
	pdiff = round(2**(224 - log(target, 2)), 8)
	return _maybe_int(pdiff)

bdiff1target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

def target2bdiff(target):
	bdiff = bdiff1target / target
	return _maybe_int(bdiff)

class shareLogFormatter:
	_re_x = re.compile(r'^\s*(\w+)\s*(?:\(\s*(.*?)\s*\))?\s*$')
	
	def __init__(self, *a, **ka):
		self._p = self.parse(*a, **ka)
	
	# NOTE: This only works for psf='%s' (default)
	def formatShare(self, *a, **ka):
		(stmt, params) = self.applyToShare(*a, **ka)
		return stmt % params
	
	def applyToShare(self, share):
		(stmt, stmtf) = self._p
		params = []
		for f in stmtf:
			params.append(f(share))
		params = tuple(params)
		return (stmt, params)
	
	@classmethod
	def parse(self, stmt, psf = '%s'):
		fmt = string.Formatter()
		pstmt = tuple(fmt.parse(stmt))
		
		stmt = ''
		fmt = []
		for (lit, field, fmtspec, conv) in pstmt:
			stmt += lit
			if not field:
				continue
			f = self.get_field(field)
			fmt.append(f)
			stmt += psf
		fmt = tuple(fmt)
		return (stmt, fmt)
	
	@classmethod
	def get_field(self, field):
		m = self._re_x.match(field)
		if m:
			if m.group(2) is None:
				# identifier
				return lambda s: s.get(field, None)
			else:
				# function
				fn = m.group(1)
				sf = self.get_field(m.group(2))
				return getattr(self, 'get_field_%s' % (fn,))(sf)
		raise ValueError('Failed to parse field: %s' % (field,))
	
	@classmethod
	def get_field_not(self, subfunc):
		return lambda s: not subfunc(s)
	
	@classmethod
	def get_field_Q(self, subfunc):
		return lambda s: subfunc(s) or '?'
	
	@classmethod
	def get_field_dash(self, subfunc):
		return lambda s: subfunc(s) or '-'
	
	@classmethod
	def get_field_YN(self, subfunc):
		return lambda s: YN(subfunc(s))
	
	@classmethod
	def get_field_target2bdiff(self, subfunc):
		return lambda s: target2bdiff(subfunc(s))
	
	@classmethod
	def get_field_target2pdiff(self, subfunc):
		return lambda s: target2pdiff(subfunc(s))
#endif

bytes_t dblsha(bytes_t b) {
	char digest[32], digest2[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, digest, b.data(), b.size());
	gcry_md_hash_buffer(GCRY_MD_SHA256, digest2, digest, 32);
	return bytes_t(&digest2[0], &digest2[32]);
}

#if 0
def swap32(b):
	o = b''
	for i in range(0, len(b), 4):
		o += b[i + 3:i - 1 if i else None:-1]
	return o

def Bits2Target(bits):
	return unpack('<L', bits[:3] + b'\0')[0] * 2**(8*(bits[3] - 3))

def LEhash2int(h):
	n = unpack('<QQQQ', h)
	n = (n[3] << 192) | (n[2] << 128) | (n[1] << 64) | n[0]
	return n

def BEhash2int(h):
	n = unpack('>QQQQ', h)
	n = (n[0] << 192) | (n[1] << 128) | (n[2] << 64) | n[3]
	return n

def tryErr(func, *a, **kw):
	IE = kw.pop('IgnoredExceptions', BaseException)
	logger = kw.pop('Logger', None)
	emsg = kw.pop('ErrorMsg', None)
	try:
		return func(*a, **kw)
	except IE:
		if logger:
			emsg = "%s\n" % (emsg,) if emsg else ""
			emsg += traceback.format_exc()
			logger.error(emsg)
		return None

class RejectedShare(ValueError):
	pass

PendingUpstream = object()
#endif


#include <queue>

bool ScheduleDict::comparer::operator() (const pq_element_t & lhs, const pq_element_t & rhs) const {
	return std::get<0>(lhs) < std::get<0>(rhs);
}

ScheduleDict::ScheduleDict() :
	_dict(),
	_heap()
{
	_build_heap();
}

void ScheduleDict::_build_heap() {
	std::vector<pq_element_t> newheap;
	for (auto it = _dict.begin(); it != _dict.end(); ++it)
		newheap.push_back(pq_element_t(it->second.first, it->first, it->second.second));
	_heap = pq_t(newheap.begin(), newheap.end());
}

time_t ScheduleDict::nextTime() {
	time_t t;
	while (true)
	{
		auto & top = _heap.top();
		t = std::get<0>(top);
		auto & k = std::get<1>(top);
		auto & o = std::get<2>(top);
		if (_dict.count(k))
			break;
		_heap.pop();
	}
	return t;
}

std::function<void()> ScheduleDict::shift() {
	std::function<void()> o;
	void *k;
	while (true)
	{
		auto & top = _heap.top();
		auto & t = std::get<0>(top);
		k = std::get<1>(top);
		o = std::get<2>(top);
		_heap.pop();
		if (_dict.count(k))
			break;
	}
	_dict.erase(k);
	return o;
}

void ScheduleDict::__setitem__(std::function<void()> & o, time_t t) {
	auto k = (void*)&o;
	_dict[k] = std::pair<time_t, std::function<void()> >(t, o);
	if (_heap.size() / 2 > _dict.size())
		_build_heap();
	else
		_heap.push(pq_element_t(t, (void*)&o, o));
}

time_t ScheduleDict::__getitem__(std::function<void()> & o) {
	return _dict[(void*)&o].first;
}

void ScheduleDict::erase(std::function<void()> & o) {
	_dict.erase((void*)&o);
	if (_dict.size() < 2)
		_build_heap();
}

size_t ScheduleDict::size() {
	return _dict.size();
}

bool ScheduleDict::empty() {
	return _dict.empty();
}
