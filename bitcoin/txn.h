#ifndef BITCOIN_TXN_H
#define BITCOIN_TXN_H

namespace bitcoin {
namespace txn {

class _TxnOutpoint {
public:
	bytes_t txid;
	uint32_t index;
	
	_TxnOutpoint(bytes_t a, uint32_t b) : txid(a), index(b) {}
	
	bool operator==(const _TxnOutpoint & b)
	{
		return txid == b.txid && index == b.index;
	}
};

class _TxnIn {
public:
	_TxnOutpoint prevout;
	bytes_t sigScript;
	uint32_t seqno;
	
	_TxnIn(_TxnOutpoint a, bytes_t b, uint32_t c) : prevout(a), sigScript(b), seqno(c) {}
};

class _TxnOut {
public:
	uint64_t amount;
	bytes_t pkScript;
	
	_TxnOut(uint64_t a, bytes_t b) : amount(a), pkScript(b) {}
};

class Txn {
public:
	uint32_t version;
	std::vector<_TxnIn> inputs;
	std::vector<_TxnOut> outputs;
	uint32_t locktime;
	bytes_t data;
	bytes_t txid;
	
	Txn(bytes_t = bytes_t());
	static Txn newclean();
	
	void setCoinbase(const bytes_t sigScript, uint32_t seqno = 0xffffffff, blkheight_t height = 0);
	void addInput(_TxnOutpoint prevout, bytes_t sigScript, uint32_t seqno = 0xffffffff);
	void addOutput(uint64_t amount, bytes_t pkScript);
	bytes_t disassemble(bool retExtra = false);
	bool isCoinbase();
	bytes_t getCoinbase();
	void assemble();
	void idhash();
};

};
};

#endif
