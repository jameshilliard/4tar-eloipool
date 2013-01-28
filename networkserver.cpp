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

#include <boost/any.hpp>
#include "networkserver.h"

//import asynchat
#include <log4cxx/logger.h>
//import os
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
//import traceback
#include "util.h"  // ScheduleDict, WithNoop, tryErr

// From Python 3.2 asynchat.find_prefix_at_end
static size_t find_prefix_at_end(bytes_t haystack, bytes_t needle) {
	size_t l = needle.size() - 1;
	while (l && bytes_t(haystack.end() - l, haystack.end()) != bytes_t(needle.begin(), needle.begin() + l))
		l -= 1;
	return l;
}

void SocketHandler::handle_close() {
	wbuf.clear();
	close();
}

void SocketHandler::handle_error() {
	//LOG4CXX_DEBUG(logger, traceback.format_exc())
	handle_close();
}

void SocketHandler::handle_read() {
	bytes_t data;
	try
	{
		data = this->recv(ac_in_buffer_size);
	}
	catch (SocketError why)
	{
		handle_error();
		return;
	}
	
	if (closeme)
		// All input is ignored from sockets we have "closed"
		return;
	
#if 0
	if isinstance(data, str) and self.use_encoding:
		data = bytes(str, self.encoding)
#endif
	BYTES_APPEND(ac_in_buffer, data);
	
	server.lastReadbuf = &ac_in_buffer;
	
	handle_readbuf();
}

// From Python 3.2 asynchat.async_chat._collect_incoming_data
void SocketHandler::collect_incoming_data(bytes_t data) {
	incoming.push_back(data);
}

// From Python 3.2 asynchat.async_chat.get_terminator
boost::any SocketHandler::get_terminator() {
	return terminator;
}

// From Python 3.2 asynchat.async_chat.set_terminator
void SocketHandler::set_terminator(bytes_t term) {
	// Set the input delimiter.  Can be a fixed string of any length, an integer, or None
#if 0
	if isinstance(term, str) and self.use_encoding:
		term = bytes(term, self.encoding)
#endif
	terminator = term;
}
void SocketHandler::set_terminator(std::vector<bytes_t> term) {
	terminator = term;
}
void SocketHandler::set_terminator(uintmax_t term) {
	terminator = term;
}
void SocketHandler::set_terminator() {
	terminator = boost::any();
}

void SocketHandler::handle_readbuf() {
	while (ac_in_buffer.size())
	{
		size_t lb = ac_in_buffer.size();
		boost::any terminator = get_terminator();
		if (terminator.empty())
		{
			// no terminator, collect it all
			collect_incoming_data(ac_in_buffer);
			ac_in_buffer.clear();
		}
		else
		if (terminator.type() == typeid(uintmax_t))
		{
			// numeric terminator
			uintmax_t n = boost::any_cast<uintmax_t>(terminator);
			if (lb < n)
			{
				collect_incoming_data(ac_in_buffer);
				ac_in_buffer.clear();
				terminator = n - lb;
			}
			else
			{
				collect_incoming_data(bytes_t(ac_in_buffer.begin(), ac_in_buffer.begin() + n));
				ac_in_buffer.erase(ac_in_buffer.begin(), ac_in_buffer.begin() + n);
				terminator = 0;
				found_terminator();
			}
		}
		else
		{
			// 3 cases:
			// 1) end of buffer matches terminator exactly:
			//    collect data, transition
			// 2) end of buffer matches some prefix:
			//    collect data to the prefix
			// 3) end of buffer does not match any prefix:
			//    collect data
			// NOTE: this supports multiple different terminators, but
			//       NOT ones that are prefixes of others...
			if (typeid(ac_in_buffer) == terminator.type())
				terminator = std::vector<bytes_t>(1, boost::any_cast<bytes_t>(terminator));
			
			const auto & terminatorlist = boost::any_cast<std::vector<bytes_t> >(terminator);
			std::vector<size_t> termidx;
			for (std::vector<bytes_t>::const_iterator it = terminatorlist.begin(); it != terminatorlist.end(); ++it)
				termidx.push_back(std::distance(ac_in_buffer.begin(), std::search(ac_in_buffer.begin(), ac_in_buffer.end(), it->begin(), it->end())));
			
			ssize_t index = -1;
			for (std::vector<size_t>::iterator it = termidx.begin(); it != termidx.end(); ++it)
				if (*it >= 0 && (index == -1 || index > *it))
					index = *it;
			
			if (index != -1)
			{
				// we found the terminator
				if (index > 0)
					// don't bother reporting the empty string (source of subtle bugs)
					collect_incoming_data(bytes_t(ac_in_buffer.begin(), ac_in_buffer.begin() + index));
				bytes_t specific_terminator = terminatorlist[std::distance(termidx.begin(), std::find(termidx.begin(), termidx.end(), index))];
				size_t terminator_len = specific_terminator.size();
				ac_in_buffer.erase(ac_in_buffer.begin(), ac_in_buffer.begin() + index + terminator_len);
				// This does the Right Thing if the terminator is changed here.
				found_terminator();
			}
			else
			{
				// check for a prefix of the terminator
				
				termidx.clear();
				for (std::vector<bytes_t>::const_iterator it = terminatorlist.begin(); it != terminatorlist.end(); ++it)
					termidx.push_back(find_prefix_at_end(ac_in_buffer, *it));
				
				index = *std::max_element(termidx.begin(), termidx.end());
				if (index)
				{
					if (index != lb)
					{
						// we found a prefix, collect up to the prefix
						collect_incoming_data(bytes_t(ac_in_buffer.begin(), ac_in_buffer.end() - index));
						ac_in_buffer = bytes_t(ac_in_buffer.end() - index, ac_in_buffer.end());
					}
					break;
				}
				else
				{
					// no prefix, collect it all
					collect_incoming_data(ac_in_buffer);
					ac_in_buffer.clear();
				}
			}
		}
	}
}

void SocketHandler::push(bytes_t data) {
	if (wbuf.empty())
	{
		// Try to send as much as we can immediately
		ssize_t bs;
		try
		{
			bs = send(socket, data.data(), data.size(), 0);
		}
		catch (...)
		{
			// Chances are we'll fail later, but anyway...
			bs = 0;
		}
		data.erase(data.begin(), data.begin() + bs);
		if (data.empty())
			return;
	}
	BYTES_APPEND(wbuf, data);
	server.register_socket_m(fd, EPOLL_READ | EPOLL_WRITE);
}

void SocketHandler::handle_timeout() {
	close();
}

void SocketHandler::handle_write() {
	if (wbuf.empty())
		// Socket was just closed by remote peer
		return;
	ssize_t bs = send(socket, wbuf.data(), wbuf.size(), 0);
	wbuf.erase(wbuf.begin(), wbuf.begin() + bs);
	if (wbuf.empty())
	{
		if (closeme)
		{
			close();
			return;
		}
		server.register_socket_m(fd, EPOLL_READ);
	}
}

// From Python 3.2 asynchat.async_chat.recv
bytes_t SocketHandler::recv(size_t buffer_size) {
	bytes_t data;
	try {
		uint8_t buf[buffer_size];
		size_t sz = ::recv(socket, &buf[0], buffer_size, 0);
		data.insert(data.begin(), &buf[0], &buf[sz]);
		
		if (data.empty())
		{
			// a closed connection is indicated by signaling
			// a read condition, and having recv() return 0.
			handle_close();
			return bytes_t();
		}
		else
		{
			return data;
		}
	}
	catch (SocketError why)
	{
		// winsock sometimes throws ENOTCONN
#if 0
		if (why.args[0] in _DISCONNECTED)
			self.handle_close()
			return b''
		else:
			raise
#endif
	}
}

void SocketHandler::close() {
	if (!wbuf.empty())
	{
		closeme = true;
		return;
	}
	if (fd == -1)
		// Already closed
		return;
	try
	{
		server.connections.erase(this);
	}
	catch (...)
	{
	}
	server.unregister_socket(fd);
	changeTask();
	::close(socket);
	fd = -1;
}

void SocketHandler::boot() {
	close();
	ac_in_buffer.clear();
}

void SocketHandler::changeTask(std::function<void()> f, time_t t) {
	tryErr(KeyError, server.rmSchedule(_Task); );
	if (f)
		_Task = server.schedule(f, t, this);
	else
		_Task = std::function<void()>();
}

SocketHandler::SocketHandler(AsyncSocketServer & server, socket_t sock, _SockAddr addr) :
	ac_in_buffer_size(4096),
	ac_out_buffer_size(4096),
	ac_in_buffer(),
	incoming(),
	wbuf(),
	closeme(false),
	server(server),
	socket(sock),
	addr(addr),
	_Task(NULL),
	fd(sock)
{
	server.register_socket(fd, *this);
	server.connections[this] = this;
	changeTask(std::bind(&SocketHandler::handle_timeout, this), time(NULL) + 15);
}

#if 0
@classmethod
def _register(cls, scls):
	for a in dir(scls):
		if a == 'final_init':
			f = lambda self, x=getattr(cls, a), y=getattr(scls, a): (x(self), y(self))
			setattr(cls, a, f)
			continue
		if a[0] == '_':
			continue
		setattr(cls, a, getattr(scls, a))
#endif


NetworkListener::NetworkListener(AsyncSocketServer & server, _SockAddr server_address, int address_family) :
	server(server),
	server_address(server_address),
	address_family(address_family)
{
	logger = log4cxx::Logger::getLogger("SocketListener");
	try
	{
		setup_socket(server_address);
	}
	catch (...)
	{
		//logger.error(server_address + traceback);
	}
}

socket_t NetworkListener::_makebind_cpp(_SockAddr server_address) {
	socket_t sock = ::socket(address_family, SOCK_STREAM, 0);
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
	setnonblocking(sock);
	{
		int v = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	}
#if 0
	bind(sock, server_address)
#endif
	return sock;
}

socket_t NetworkListener::_makebind_su(_SockAddr server_address) {
	if (address_family != AF_INET6)
		throw NotImplementedError();
	
#if 0
	from bindservice import bindservice
	(node, service) = server_address
	if not node: node = ''
	if not service: service = ''
	fd = bindservice(str(node), str(service))
	sock = socket.fromfd(fd, socket.AF_INET6, socket.SOCK_STREAM)
	sock.setblocking(0)
	return sock
#endif
}

socket_t NetworkListener::_makebind(_SockAddr server_address) {
	try
	{
		return _makebind_cpp(server_address);
	}
	catch (std::exception e)
	{
		try
		{
			return _makebind_su(server_address);
		}
		catch (...)
		{
		}
		throw;
	}
}

void NetworkListener::setup_socket(_SockAddr server_address) {
	socket_t sock = _makebind(server_address);
	listen(sock, 100);
	server.register_socket(sock, *this);
	socket = sock;
}

void NetworkListener::handle_read() {
	_SockAddr addr;
	socket_t conn;
	{
		char buf[0x100];
		socklen_t bufsz = sizeof(buf);
		conn = accept(socket, (struct sockaddr*)&buf[0], &bufsz);
		if (conn == -1)
			throw SocketError(errno);
		auto sa = (struct sockaddr *)&buf[0];
		switch (sa->sa_family) {
			case AF_INET6:
			{
				auto in6 = (struct sockaddr_in6*)sa;
				addr.service = in6->sin6_port;
				char cbuf[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, (void*)&in6->sin6_addr, &cbuf[0], sizeof(cbuf)))
					addr.node.insert(addr.node.end(), &cbuf[0], &cbuf[strlen(cbuf)]);
			}
			default:
				break;
		}
	}
	if (server.rejecting)
	{
		close(conn);
		return;
	}
	setnonblocking(conn);
	server.RequestHandlerClass(server, conn, addr);
}

void NetworkListener::handle_error() {
	// Ignore errors... like socket closing on the queue
}


_Waker::_Waker(AsyncSocketServer & server, socket_t fd) :
	server(server),
	fd(fd)
{
	logger = log4cxx::Logger::getLogger("Waker for %s"); // server.__class__.__name__
}

void _Waker::handle_read() {
	char bufc;
	ssize_t sz = read(fd, &bufc, 1);
	if (!sz)
		LOG4CXX_ERROR(logger, "Got EOF on socket");
	LOG4CXX_DEBUG(logger, "Read wakeup");
}


AsyncSocketServer::AsyncSocketServer(_SocketHandlerFactory_t RequestHandlerClass) :
	waker(false),
	schMT(false),
	_fd(),
	connections(),
	_sch(),
	_schEH(),
	TrustedForwarders(),
	RequestHandlerClass(RequestHandlerClass),
	running(false),
	keepgoing(true),
	rejecting(false)
{
	logger = log4cxx::Logger::getLogger("SocketServer");
	
	if (ServerName.empty())
		ServerName = "Ciloipool++";
	
	_epoll = epoll_create(1);
	if (_epoll == -1)
		throw SocketError{errno};
	
	if (schMT)
		_schLock = new MutexLockable();
	else
		_schLock = new FakeLockable();
	
	if (waker)
	{
		socket_t pipefd[2];
		if (-1 == pipe(pipefd))
			throw SocketError{errno};
		socket_t & r = pipefd[0];
		socket_t & w = pipefd[1];
		_Waker o(*this, r);
		register_socket(r, o);
		waker = w;
	}
}

void AsyncSocketServer::register_socket(socket_t fd, _SocketHandlerInterface & o, uint32_t eventmask) {
	epoll_event ev{};
	ev.events = eventmask;
	if (-1 == epoll_ctl(_epoll, EPOLL_CTL_ADD, fd, &ev))
		throw SocketError{errno};
	_fd[fd] = &o;
}

void AsyncSocketServer::register_socket_m(socket_t fd, uint32_t eventmask) {
	epoll_event ev{};
	ev.events = eventmask;
	if (-1 == epoll_ctl(_epoll, EPOLL_CTL_MOD, fd, &ev))
		throw SocketError{errno};
}

void AsyncSocketServer::unregister_socket(socket_t fd) {
	_fd.erase(fd);
	if (-1 == epoll_ctl(_epoll, EPOLL_CTL_DEL, fd, (struct epoll_event*)&fd))
		throw SocketError{errno};
}

std::function<void()> & AsyncSocketServer::schedule(std::function<void()> & task, time_t startTime, _SocketHandlerInterface *errHandler) {
	auto task_c = new std::function<void()>(task);
	{
		ScopedLock lock(*_schLock);
		
		_sch.__setitem__(*task_c, startTime);
		if (errHandler)
			_schEH[task_c] = errHandler;
	}
	return *task_c;
}

void AsyncSocketServer::rmSchedule(std::function<void()> & task) {
	ScopedLock lock(*_schLock);
	
	_sch.erase(task);
	void *k = &task;
	if (_schEH.count(k))
		_schEH.erase(k);
	delete &task;
}

void AsyncSocketServer::pre_schedule() {
}

void AsyncSocketServer::wakeup() {
	if (!waker)
		throw NotImplementedError{"Class `%s' did not enable waker"};  // self.__class__.__name__
	char v = 1;
	write(waker, &v, 1);  // to break out of the epoll
}

void AsyncSocketServer::final_init() {
}

void AsyncSocketServer::boot_all() {
	for (auto it = connections.begin(); it != connections.end(); ++it)
		tryErr(..., it->second->boot(); );
}

void AsyncSocketServer::serve_forever() {
	running = true;
	final_init();
	while (keepgoing) {
		doing = "pre-schedule";
		pre_schedule();
		doing = "schedule";
		int timeout;
		if (_sch.size())
		{
			time_t timeNow = time(NULL);
			while (true)
			{
				std::function<void()> f;
				{
					ScopedLock lock(*_schLock);
					
					if (_sch.empty())
					{
						timeout = -1;
						break;
					}
					time_t timeNext = _sch.nextTime();
					if (timeNow < timeNext)
					{
						timeout = timeNext - timeNow;
						break;
					}
					f = _sch.shift();
				}
				void *k = &f;
				_SocketHandlerInterface *EH = NULL;
				if (_schEH.count(k))
				{
					EH = _schEH[k];
					_schEH.erase(k);
				}
				try
				{
					f();
				}
				catch (SocketError)
				{
					if (EH) tryErr(..., EH->handle_error(); );
				}
				catch (...)
				{
					//self.logger.error(traceback.format_exc())
					if (EH) tryErr(..., EH->handle_close(); );
				}
				delete &f;
			}
		}
		else
		{
			timeout = -1;
		}
		
		doing = "poll";
		struct epoll_event events[0x10];
		int events_sz = epoll_wait(_epoll, events, 0x10, timeout);
		if (events_sz == -1)
			continue;
		doing = "events";
		for (int i = 0; i < events_sz; ++i)
		{
			socket_t & fd = events[i].data.fd;
			uint32_t & e = events[i].events;
			
			auto o = _fd[fd];
			lastHandler = o;
			try
			{
				if (e & EPOLL_READ)
					o->handle_read();
				if (e & EPOLL_WRITE)
					o->handle_write();
			}
			catch (SocketError)
			{
				tryErr(..., o->handle_error(); );
			}
			catch (...)
			{
				//self.logger.error(traceback.format_exc())
				tryErr(..., o->handle_error(); );
			}
		}
	}
	doing = NULL;
	running = false;
}
