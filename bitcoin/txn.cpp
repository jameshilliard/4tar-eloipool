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
#include "txn.h"

#include "script.h"
#include "varlen.h"  // varlenDecode, varlenEncode
#include "../util.h"  // dblsha
//from struct import pack, unpack

namespace bitcoin {
	namespace txn {

bytes_t _nullprev(32);

Txn::Txn(bytes_t data) {
	if (!data.empty())
	{
		this->data = data;
		idhash();
	}
}

Txn Txn::newclean() {
	Txn o;
	o.version = 1;
	o.inputs.clear();
	o.outputs.clear();
	o.locktime = 0;
	return o;
}

void Txn::setCoinbase(const bytes_t sigScript_in, uint32_t seqno, blkheight_t height) {
	bytes_t sigScript;
	if (height)
		// NOTE: This is required to be the minimum valid length by BIP 34
		sigScript = bitcoin::script::encodeUNum(height);
	BYTES_APPEND(sigScript, sigScript_in);
	inputs.clear();
	inputs.push_back(_TxnIn(_TxnOutpoint(_nullprev, 0xffffffff), sigScript, seqno));
}

void Txn::addInput(_TxnOutpoint prevout, bytes_t sigScript, uint32_t seqno) {
	inputs.push_back(_TxnIn(prevout, sigScript, seqno));
}

void Txn::addOutput(uint64_t amount, bytes_t pkScript) {
	outputs.push_back(_TxnOut(amount, pkScript));
}

bytes_t Txn::disassemble(bool retExtra) {
	version = unpack_LE_L(data);
	unsigned _rc = 4;
	unsigned *rc = &_rc;
	
	bytes_t data = this->data;
	data.erase(data.begin(), data.begin() + 4);
	uint64_t inputCount = varlenDecode(data, data, rc);
	std::vector<_TxnIn> inputs;
	for (uint64_t i = 0; i < inputCount; ++i)
	{
		_TxnOutpoint prevout(bytes_t(data.begin(), data.begin() + 32), unpack_LE_L(&data[32]));
		rc[0] += 36;
		data.erase(data.begin(), data.begin() + 36);
		uint64_t sigScriptLen = varlenDecode(data, data, rc);
		bytes_t sigScript(data.begin(), data.begin() + sigScriptLen);
		uint32_t seqno = unpack_LE_L(&data[sigScriptLen]);
		data.erase(data.begin(), data.begin() + sigScriptLen + 4);
		rc[0] += sigScriptLen + 4;
		inputs.push_back(_TxnIn(prevout, sigScript, seqno));
	}
	this->inputs = inputs;
	
	uint64_t outputCount = varlenDecode(data, data, rc);
	std::vector<_TxnOut> outputs;
	for (uint64_t i = 0; i < outputCount; ++i)
	{
		uint64_t amount = unpack_LE_Q(data);
		rc[0] += 8;
		data.erase(data.begin(), data.begin() + 8);
		uint64_t pkScriptLen = varlenDecode(data, data, rc);
		bytes_t pkScript(data.begin(), data.begin() + pkScriptLen);
		data.erase(data.begin(), data.begin() + pkScriptLen);
		rc[0] += pkScriptLen;
		outputs.push_back(_TxnOut(amount, pkScript));
	}
	this->outputs = outputs;
	
	locktime = unpack_LE_L(data);
	if (!retExtra)
		asserte(data.size() == 4);
	else
	{
		asserte(data == bytes_t(this->data.begin() + rc[0], this->data.end()));
		data.erase(data.begin(), data.begin() + 4);
		rc[0] += 4;
		this->data.erase(data.begin() + rc[0], data.end());
		return data;
	}
}

bool Txn::isCoinbase() {
	return inputs.size() == 1 && inputs[0].prevout == _TxnOutpoint(_nullprev, 0xffffffff);
}

bytes_t Txn::getCoinbase() {
	return this->inputs[0].sigScript;
}

void Txn::assemble() {
	bytes_t data;
	pack_LE_L(data, version);
	
	BYTES_APPEND(data, varlenEncode(inputs.size()));
	for (std::vector<_TxnIn>::iterator it = inputs.begin(); it != inputs.end(); ++it)
	{
		_TxnOutpoint & prevout = it->prevout;
		bytes_t & sigScript = it->sigScript;
		uint32_t & seqno = it->seqno;
		
		BYTES_APPEND(data, prevout.txid);
		pack_LE_L(data, prevout.index);
		BYTES_APPEND(data, varlenEncode(sigScript.size()));
		BYTES_APPEND(data, sigScript);
		pack_LE_L(data, seqno);
	}
	
	BYTES_APPEND(data, varlenEncode(outputs.size()));
	for (std::vector<_TxnOut>::iterator it = outputs.begin(); it != outputs.end(); ++it)
	{
		uint64_t & amount = it->amount;
		bytes_t & pkScript = it->pkScript;
		
		pack_LE_Q(data, amount);
		BYTES_APPEND(data, varlenEncode(pkScript.size()));
		BYTES_APPEND(data, pkScript);
	}
	
	pack_LE_L(data, locktime);
	
	this->data = data;
	idhash();
}

void Txn::idhash() {
	txid = dblsha(data);
}

// Txn tests
INIT(test) {
	bytes_t d{1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	bytes_t x=d;
	Txn t(d);
	assert(t.txid == BYTES('C', 0xec, 'z', 'W', 0x9f, 'U', 'a', 0xa4, '*', '~', 0x96, '7', 0xad, 'A', 'V', 'g', '\'', '5', 0xa6, 'X', 0xbe, '\'', 'R', 0x18, 0x18, 1, 0xf7, '#', 0xba, '3', 0x16, 0xd2));
	t.disassemble();
	t.assemble();
	assert(t.data == d);
	assert(!t.isCoinbase());
	t = Txn::newclean();
	t.addInput(_TxnOutpoint(bytes_t(32, ' '), 0), BYTES('I','N','P','U','T'));
	t.addOutput(0x10000, BYTES('O','U','T','P','U','T'));
	t.assemble();
	assert(t.txid == BYTES('>', '`', 0x97, 0xec, 'u', 0x8e, 0xb5, 0xef, 0x19, 'k', 0x17, 'd', 0x96, 's', 'w', 0xb1, 0xf1, 0x9b, 'O', 0x1c, '6', 0xa0, 0xbe, 0xf7, 'N', 0xed, 0x13, 'j', 0xfd, 'H', 'F', 0x1a));
	t.disassemble();
	t.assemble();
	assert(t.txid == BYTES('>', '`', 0x97, 0xec, 'u', 0x8e, 0xb5, 0xef, 0x19, 'k', 0x17, 'd', 0x96, 's', 'w', 0xb1, 0xf1, 0x9b, 'O', 0x1c, '6', 0xa0, 0xbe, 0xf7, 'N', 0xed, 0x13, 'j', 0xfd, 'H', 'F', 0x1a));
	assert(!t.isCoinbase());
	t = Txn::newclean();
	t.setCoinbase(BYTES('C','O','I','N','B','A','S','E'));
	t.addOutput(0x10000, BYTES('O','U','T','P','U','T'));
	assert(t.isCoinbase());
	assert(t.getCoinbase() == BYTES('C','O','I','N','B','A','S','E'));
	t.assemble();
	assert(t.txid == BYTES('n', 0xb9, 0xdc, 0xef, 0xe9, 0xdb, '(', 'R', 0x8d, 'C', '~', '-', 0xef, '~', 0x88, 'd', 0x15, '+', 'X', 0x13, '&', 0xb7, 0xbc, '$', 0xb1, 'h', 0xf3, 'g', '=', 0x9b, '~', 'V'));
}

	};
};
