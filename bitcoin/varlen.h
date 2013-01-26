#ifndef BITCOIN_VARLEN_H
#define BITCOIN_VARLEN_H

#include <stdint.h>
#include <vector>

extern unsigned _varlen_ignoredrc;

extern uint64_t varlenDecode(const std::vector<uint8_t> b, std::vector<uint8_t> &out_b, unsigned *rc = &_varlen_ignoredrc);
extern std::vector<uint8_t> varlenEncode(uint64_t n);

#endif
