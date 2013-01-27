#ifndef UTIL_H
#define UTIL_H

extern bytes_t dblsha(bytes_t);

#define tryErr(e, ...)  do { try { __VA_ARGS__ } catch (e) {} } while(0)

#endif
