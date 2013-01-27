#ifndef TWEAKS_H
#define TWEAKS_H

#include <stdint.h>
#include <vector>

#define INIT(name) __attribute__((constructor)) static void __init_ ## name ()

typedef std::vector<uint8_t> bytes_t;
#define BYTES(...)  bytes_t({__VA_ARGS__})

typedef uint64_t blkheight_t;

#define unpack_LE_H(data) ((data)[0] | (((uint16_t)((data)[1])) << 8))
#define unpack_LE_L(data) (unpack_LE_H(data) | (((uint32_t)unpack_LE_H(&(data)[2])) << 16))
#define unpack_LE_Q(data) (unpack_LE_L(data) | (((uint64_t)unpack_LE_L(&(data)[4])) << 32))

#define pack_LE_H(v, n)  do {  \
	uint16_t _tmp_LE_H = n;  \
	v.push_back(_tmp_LE_H & 0xff);  \
	v.push_back((_tmp_LE_H & 0xff00) >> 8);  \
} while(0)
#define pack_LE_L(v, n)  do {  \
	uint32_t _tmp_LE_L = n;  \
	pack_LE_H(v, _tmp_LE_L & 0xffff);  \
	pack_LE_H(v, (_tmp_LE_L & 0xffff0000) >> 16);  \
} while(0)
#define pack_LE_Q(v, n)  do {  \
	uint64_t _tmp_LE_Q = n;  \
	pack_LE_L(v, _tmp_LE_Q & 0xffffffff);  \
	pack_LE_L(v, (_tmp_LE_Q & 0xffffffff00000000) >> 32);  \
} while(0)

#define BYTES_APPEND(v, expr)  do {  \
	bytes_t tmp = expr;  \
	v.insert(v.end(), tmp.begin(), tmp.end());  \
} while(0)

struct ValueError {
	const char *err;
};

struct AssertionError {};
#define asserte(expr) do {  \
	if (!(expr))  \
		throw AssertionError();  \
} while(0)

#endif
