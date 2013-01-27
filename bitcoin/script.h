#ifndef BITCOIN_SCRIPT_H
#define BITCOIN_SCRIPT_H

#include <inttypes.h>
#include <string>

namespace bitcoin {
namespace script {

class BitcoinScript {
	static bytes_t toAddress(std::string);
};

extern unsigned countSigOps(bytes_t);
extern bytes_t encodeUNum(uintmax_t n);

template <typename T>
bytes_t encodeNum(T n) {
	if (n == 0)
		return BYTES(0);
	if (n > 0)
		return encodeUNum(n);
	bytes_t s = encodeUNum(imaxabs(n));
	s[s.size()-1] |= 0x80;
	return s;
}

};
};

#endif
