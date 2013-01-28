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

#define USE_BITCOIN_TXN

#include "tweaks.h"
#include "merkletree.h"

#ifdef USE_BITCOIN_TXN
#include "bitcoin/txn.h"
#else
class bitcoin::txn::Txn {
	bytes_t data;
};
#endif
#include "util.h"  // dblsha

MerkleTree::MerkleTree(data_vec_t data, bool detailed) :
	data(data),
	detail(NULL)
{
	recalculate(detailed);
}

void MerkleTree::recalculate(bool detailed) {
	data_vec_t L = data;
	std::vector<bytes_t> steps;
	data_vec_t *detail;
	data_vec_t PreL;
	int StartL;
	if (detailed)
	{
		detail = new data_vec_t;
		StartL = 0;
	}
	else
	{
		detail = NULL;
		PreL.push_back(bytes_t());
		StartL = 2;
	}
	size_t Ll = L.size();
	if (detailed || Ll > 1)
	{
		if (((Ll > 1) ? L[1] : L[0]).which() == 1)
			for (auto it = L.begin(); it != L.end(); ++it)
				if (it->which() == 1)
					*it = boost::get<bitcoin::txn::Txn>(*it).txid;
		while (true)
		{
			if (detailed)
				detail->insert(detail->end(), L.begin(), L.end());
			if (Ll == 1)
				break;
			steps.push_back(boost::get<bytes_t>(L[1]));
			if (Ll % 2)
				L.push_back(L.back());
			
			data_vec_t newL = PreL;
			for (int i = StartL; i < Ll; i += 2)
			{
				bytes_t combined = boost::get<bytes_t>(L[i]);
				BYTES_APPEND(combined, boost::get<bytes_t>(L[i + 1]));
				newL.push_back(dblsha(combined));
			}
			L = std::move(newL);
			
			Ll = L.size();
		}
	}
	_steps = std::move(steps);
	delete this->detail;
	this->detail = detail;
}

bytes_t MerkleTree::withFirst(data_item_t f_in) {
	bytes_t f;
	switch (f_in.which()) {
		case 0:
			f = boost::get<bytes_t>(f_in);
			break;
		case 1:
			f = boost::get<bitcoin::txn::Txn>(f_in).txid;
			break;
		default:
			throw NotImplementedError();
	}
	for (auto it = _steps.begin(); it != _steps.end(); ++it)
	{
		BYTES_APPEND(f, *it);
		f = dblsha(f);
	}
	return f;
}

bytes_t MerkleTree::merkleRoot() {
	return withFirst(data[0]);
}

// MerkleTree tests
INIT(test) {
	std::vector<bytes_t> txidlist;
	txidlist.push_back(bytes_t());
	txidlist.push_back(BYTES(0x99,0x9d,0x2c,0x8b,0xb6,0xbd,0xa0,0xbf,
	                         0x78,0x4d,0x9e,0xbe,0xb6,0x31,0xd7,0x11,
	                         0xdb,0xbb,0xfe,0x1b,0xc0,0x06,0xea,0x13,
	                         0xd6,0xad,0x0d,0x6a,0x26,0x49,0xa9,0x71));
	txidlist.push_back(BYTES(0x3f,0x92,0x59,0x4d,0x5a,0x3d,0x7b,0x4d,
	                         0xf2,0x9d,0x7d,0xd7,0xc4,0x6a,0x0d,0xac,
	                         0x39,0xa9,0x6e,0x75,0x1b,0xa0,0xfc,0x9b,
	                         0xab,0x54,0x35,0xea,0x5e,0x22,0xa1,0x9d));
	txidlist.push_back(BYTES(0xa5,0x63,0x3f,0x03,0x85,0x5f,0x54,0x1d,
	                         0x8e,0x60,0xa6,0x34,0x0f,0xc4,0x91,0xd4,
	                         0x97,0x09,0xdc,0x82,0x1f,0x3a,0xcb,0x57,
	                         0x19,0x56,0xa8,0x56,0x63,0x7a,0xdc,0xb6));
	txidlist.push_back(BYTES(0x28,0xd9,0x7c,0x85,0x0e,0xaf,0x91,0x7a,
	                         0x4c,0x76,0xc0,0x24,0x74,0xb0,0x5b,0x70,
	                         0xa1,0x97,0xea,0xef,0xb4,0x68,0xd2,0x1c,
	                         0x22,0xed,0x11,0x0a,0xfe,0x8e,0xc9,0xe0));
	MerkleTree mt(txidlist);
	assert(
		BYTES(0x82,0x29,0x3f,0x18,0x2d,0x5d,0xb0,0x7d,
		      0x08,0xac,0xf3,0x34,0xa5,0xa9,0x07,0x01,
		      0x2b,0xbb,0x99,0x90,0x85,0x15,0x57,0xac,
		      0x0e,0xc0,0x28,0x11,0x60,0x81,0xbd,0x5a) ==
		mt.withFirst(BYTES(0xd4,0x3b,0x66,0x9f,0xb4,0x2c,0xfa,0x84,
		                   0x69,0x5b,0x84,0x4c,0x04,0x02,0xd4,0x10,
		                   0x21,0x3f,0xaa,0x4f,0x3e,0x66,0xcb,0x72,
		                   0x48,0xf6,0x88,0xff,0x19,0xd5,0xe5,0xf7))
	);
	
	bytes_t d = BYTES(1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	bytes_t dh = BYTES('C', 0xec, 'z', 'W', 0x9f, 'U', 'a', 0xa4, '*', '~', 0x96, '7', 0xad, 'A', 'V', 'g', '\'', '5', 0xa6, 'X', 0xbe, '\'', 'R', 0x18, 0x18, 0x01, 0xf7, '#', 0xba, '3', 0x16, 0xd2);
	bitcoin::txn::Txn t(d);
	MerkleTree m(std::vector<bitcoin::txn::Txn>(1, t));
	assert(m.merkleRoot() == dh);
	bitcoin::txn::Txn u = bitcoin::txn::Txn::newclean();
	u.addInput(bitcoin::txn::_TxnOutpoint(bytes_t(32, ' '), 0), bytes_t());
	u.assemble();
	m.data.push_back(u);
	m.recalculate();
	bytes_t mr = BYTES('q', 0xe1, 0x9a, '3', '\'', 0x0f, '>', 0xbf, 'T', 'v', 0xc8, 0x90, 0x81, 0x80, '2', 0xe3, 0xb7, 'u', 0x96, 0xdd, 'j', 'P', '4', 0xe3, 0x19, 0xf3, 0xf0, 0xc5, 'A', '4', 0xc0, 0xdb);
	assert(m.merkleRoot() == mr);
	bytes_t step = BYTES(0xb0, 0x91, 't', 0x84, '%', 0x9d, 'g', 0x82, '7', 0xc5, 0xbf, 0x94, 0xf0, '"', 0x94, 0xaf, 'N', '[', 0x0c, 0xee, 'l', 'F', 0xd9, 0x1b, 0x13, 'q', 0xd3, 0xdf, 0x83, 0xe6, 0x01, 'g');
	assert(m._steps == std::vector<bytes_t>(1, step));
	m.recalculate(true);
#define MYV(v, i) (boost::get<bytes_t>((v)[i]))
	assert(m.detail->size() == 3 && MYV(*m.detail, 0) == dh && MYV(*m.detail, 1) == step && MYV(*m.detail, 2) == mr);
	std::vector<bytes_t> tmp;
	tmp.push_back(t.txid);
	tmp.push_back(u.txid);
	m = MerkleTree(tmp);
	assert(m.merkleRoot() == mr);
	assert(m._steps == std::vector<bytes_t>(1, step));
	m.recalculate(true);
	assert(m.detail->size() == 3 && MYV(*m.detail, 0) == dh && MYV(*m.detail, 1) == step && MYV(*m.detail, 2) == mr);
}
