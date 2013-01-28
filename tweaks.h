#ifndef TWEAKS_H
#define TWEAKS_H

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

#define INIT(name) __attribute__((constructor)) static void __init_ ## name ()

typedef std::vector<uint8_t> bytes_t;
#define BYTES(...)  bytes_t({__VA_ARGS__})

typedef uint64_t blkheight_t;

typedef int socket_t;

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

class KeyError : std::exception {};
struct NotImplementedError {
	const char *err;
};
class SocketError : std::exception {
public:
	SocketError(int sck_errno) : std::exception(), sck_errno(sck_errno) {}
	int sck_errno;
};
struct ValueError {
	const char *err;
};

struct AssertionError {};
#define asserte(expr) do {  \
	if (!(expr))  \
		throw AssertionError();  \
} while(0)

#define setnonblocking(sck)  fcntl(sck, F_SETFL, fcntl(sck, F_GETFL, 0) | O_NONBLOCK);

class SomeLockable {
public:
	virtual void lock() = 0;
	virtual bool try_lock() = 0;
	virtual void unlock() = 0;
};

class FakeLockable : public SomeLockable {
public:
	virtual void lock() {};
	virtual bool try_lock() { return true; };
	virtual void unlock() {};
};

class MutexLockable : public SomeLockable {
public:
	virtual void lock() { mutex.lock(); };
	virtual bool try_lock() { return mutex.try_lock(); };
	virtual void unlock() { mutex.unlock(); }
private:
	boost::mutex mutex;
};

typedef boost::lock_guard<SomeLockable> ScopedLock;

template <typename T>
std::basic_string<T> formatdate(boost::posix_time::ptime t) {
	std::basic_stringstream<T> s;
	// FIXME: "Fri, 09 Nov 2001 01:08:47 -0000"
	static boost::posix_time::time_facet facet("%Y%m%d_%H%M%S");
	std::locale loc(s.getloc(), &facet);
	s.imbue(loc);
	s << t;
	return s.str();
}

template <typename T, typename U, typename V>
void SETDEFAULT(T & dict, U & key, V & def) {
	if (!dict.count(key))
		dict[key] = def;
}

#endif
