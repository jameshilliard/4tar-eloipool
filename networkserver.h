#ifndef NETWORKSERVER_H
#define NETWORKSERVER_H

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include <sys/epoll.h>

#include <functional>
#include <vector>

#include <boost/any.hpp>

#include <log4cxx/logger.h>

#include "tweaks.h"

#include "util.h"

#define EPOLL_READ (EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP)
#define EPOLL_WRITE EPOLLOUT

class AsyncSocketServer;

class _SockAddr {
public:
	std::string node;
	uint16_t service;
};

class _SocketHandlerInterface {
public:
	virtual void handle_read() { throw NotImplementedError(); };
	virtual void handle_write() { throw NotImplementedError(); };
	virtual void handle_error() { throw NotImplementedError(); };
	virtual void handle_close() { throw NotImplementedError(); };
	virtual void boot() { throw NotImplementedError(); };
};

typedef _SocketHandlerInterface *(*_SocketHandlerFactory_t)(AsyncSocketServer & server, socket_t sck, _SockAddr addr);
template <typename T>
_SocketHandlerInterface *_SocketHandlerFactory(AsyncSocketServer & server, socket_t sck, _SockAddr addr) {
	return new T(server, sck, addr);
}

class SocketHandler : public _SocketHandlerInterface {
public:
	SocketHandler();
	SocketHandler(AsyncSocketServer & server, socket_t sock, _SockAddr addr);
	
	virtual void handle_close();
	virtual void handle_error();
	virtual void handle_read();
	virtual void handle_readbuf();
	virtual void collect_incoming_data(bytes_t);
	virtual boost::any get_terminator();
	virtual void set_terminator(uintmax_t);
	virtual void set_terminator(bytes_t);
	virtual void set_terminator(std::vector<bytes_t>);
	virtual void set_terminator();
	virtual void push(bytes_t);
	virtual void handle_timeout();
	virtual void handle_write();
	virtual bytes_t recv(size_t buffer_size);
	virtual void close();
	virtual void boot();
	void changeTask(std::function<void()> f = std::function<void()>(), time_t t = 0);
	virtual void found_terminator() = 0;
	
	AsyncSocketServer & server;
	socket_t socket;
	socket_t fd;
	size_t ac_in_buffer_size;
	size_t ac_out_buffer_size;
	bytes_t ac_in_buffer;
	std::vector<bytes_t> incoming;
	bytes_t wbuf;
	bool closeme;
	boost::any terminator;
	_SockAddr addr;
	std::function<void()> _Task;
};

class NetworkListener : public _SocketHandlerInterface {
public:
	NetworkListener(AsyncSocketServer & server, _SockAddr server_address, int address_family = AF_INET6);
	void setup_socket(_SockAddr server_address);
	void handle_read();
	void handle_error();
	
	AsyncSocketServer & server;
	int address_family;

private:
	socket_t _makebind_cpp(_SockAddr server_address);
	socket_t _makebind_su(_SockAddr server_address);
	socket_t _makebind(_SockAddr server_address);
	
	log4cxx::LoggerPtr logger;
	socket_t socket;
	_SockAddr server_address;
};

class _Waker : public _SocketHandlerInterface {
public:
	_Waker(AsyncSocketServer & server, socket_t fd);
	
	void handle_read();

private:
	AsyncSocketServer & server;
	socket_t fd;

private:
	log4cxx::LoggerPtr logger;
};

class AsyncSocketServer {
public:
	AsyncSocketServer(_SocketHandlerFactory_t);
	
	void register_socket(socket_t fd, _SocketHandlerInterface & o, uint32_t eventmask = EPOLL_READ);
	void register_socket_m(socket_t fd, uint32_t eventmask);
	void unregister_socket(socket_t fd);
	std::function<void()> & schedule(std::function<void()> & task, time_t startTime, _SocketHandlerInterface *errHandler = NULL);
	void rmSchedule(std::function<void()> & task);
	virtual void pre_schedule();
	void wakeup();
	virtual void final_init();
	void boot_all();
	void serve_forever();
	
	_SocketHandlerFactory_t RequestHandlerClass;
	std::string ServerName;
	socket_t waker;
	bool schMT;
	bool running;
	volatile bool keepgoing;
	bool rejecting;
	const char *doing;
	std::map<void *, _SocketHandlerInterface *> connections;
	bytes_t *lastReadbuf;
	_SocketHandlerInterface *lastHandler;

private:
	log4cxx::LoggerPtr logger;
	socket_t _epoll;
	std::map<socket_t, _SocketHandlerInterface *> _fd;
	ScheduleDict _sch;
	SomeLockable *_schLock;
	std::map<void *, _SocketHandlerInterface *> _schEH;
	std::vector<std::string> TrustedForwarders;
};

#endif
