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

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include "tweaks.h"
#include "httpserver.h"

// base64
#include <boost/date_time/posix_time/posix_time.hpp>
//from gzip import GzipFile
//import io
#include <log4cxx/logger.h>
#include "networkserver.h"
//import os
#include <boost/filesystem.hpp>
//import re
//import stat
//from struct import pack
#include <time.h>  // mktime, time
//import traceback

namespace httpserver {

#if 0
INIT(AGPL_Check) {
	// It is not legal to bypass or lie to this check. See LICENSE file for details.
	try
	{
		namespace fs = boost::filesystem;
		fs::path _srcdir( = os.path.dirname(os.path.abspath(__file__))
		if os.path.exists(_srcdir + '/.I_swear_that_I_am_Luke_Dashjr'):
			_SourceFiles = None
		else:
			_SourceFiles = os.popen('cd \'%s\' && git ls-files' % (_srcdir,)).read().split('\n')
			try:
				_SourceFiles.remove('')
			except ValueError:
				pass
			if len(_SourceFiles) < 2:
				raise RuntimeError('Unknown error')
			_SourceFiles = tuple(x.encode('utf8') for x in _SourceFiles)
			_GitDesc = os.popen('cd \'%s\' && git describe --dirty --always' % (_srcdir,)).read().strip().encode('utf8')
	except BaseException as e:
		logging.getLogger('Licensing').critical('Error getting list of source files! AGPL requires this. To fix, be sure you are using git for Ciloipool++.\n' + traceback.format_exc())
		import sys
		sys.exit(1)
}
#endif

static std::map<int, std::string> HTTPStatus{
	{200, "OK"},
	{401, "Unauthorized"},
	{404, "Not Found"},
	{405, "Method Not Allowed"},
	{500, "Internal Server Error"},
};

static std::map<std::string, bool> default_quirks;

void HTTPHandler::sendReply(int status, bytes_t *body, std::map<std::string, std::string> headers) {
	if (replySent)
		throw RequestAlreadyHandled();
	std::string ThisHTTPStatus("Unknown");
	try { ThisHTTPStatus = HTTPStatus.at(status); } catch (std::out_of_range) {}
	std::string buf = (boost::format("HTTP/1.1 %d %s\r\n") % status % ThisHTTPStatus).str();
	headers["Date"] = formatdate<char>(boost::posix_time::second_clock::universal_time());
	SETDEFAULT(headers, "Server", "Ciloipool++");
#if 0
	if not _SourceFiles is None:
		headers.setdefault('X-Source-Code', '/src/')
#endif
	if (!body)
		SETDEFAULT(headers, "Transfer-Encoding", "chunked");
	else
	{
#if 0
		if quirks.count("gzip")
		{
			headers["Content-Encoding"] = "gzip";
			headers["Vary"] = "Content-Encoding";
			gz = io.BytesIO()
			with GzipFile(fileobj=gz, mode='wb') as raw:
				raw.write(body)
			body = gz.getvalue()
		}
#endif
		headers["Content-Length"] = body->size();
	}
	for (auto it = headers.begin(); it != headers.end(); ++it)
	{
		if (it->second.empty())
			continue;
		buf += (boost::format("%s: %s\r\n") % it->first % it->second).str();
	}
	buf += "\r\n";
	bytes_t bbuf(buf.begin(), buf.end());
	replySent = true;
	if (!body)
	{
		push(bbuf);
		return;
	}
	BYTES_APPEND(bbuf, *body);
	push(bbuf);
	throw RequestHandled();
}

void HTTPHandler::doError(std::string reason, int code, std::map<std::string, std::string> headers) {
	SETDEFAULT(headers, "Content-Type", "text/plain");
	bytes_t reasonb(reason.begin(), reason.end());
	sendReply(500, &reasonb, headers);
}

static void doHeader_accept_encoding(HTTPHandler & self, bytes_t value) {
	static bytes_t gzip = BYTES('g', 'z', 'i', 'p');
	if (std::search(value.begin(), value.end(), gzip.begin(), gzip.end()) != value.end())
		self.quirks["gzip"] = true;
}

static void doHeader_authorization(HTTPHandler & self, bytes_t valueb) {
	std::vector<bytes_t> value;
//	std::copy(istream_iterator<bytes_t>(std::istringstream(valueb)),
//	          istream_iterator<bytes_t>(),
//	          back_inserter<std::vector<bytes_t> >(value));
	boost::split(value, valueb, boost::is_any_of(" "));
	if (value.size() != 2 || value[0] != BYTES('B','a','s','i','c'))
	{
		self.doError("Bad Authorization header");
		return;
	}
#if 0
	value = b64decode(value[1])
	(un, pw, *x) = value.split(b':', 1) + [None]
	valid = False
	try:
		valid = self.checkAuthentication(un, pw)
	except:
		return self.doError('Error checking authorization')
	if valid:
		self.Username = un.decode('utf8')
#endif
}

static void doHeader_connection(HTTPHandler & self, bytes_t value) {
	if (value == BYTES('c','l','o','s','e'))
		self.quirks["close"] = false;
}

static void doHeader_content_length(HTTPHandler & self, bytes_t value) {
	value.push_back(0);
	self.CL = atoll((const char *)value.data());
}

static void doHeader_x_forwarded_for(HTTPHandler & self, bytes_t value) {
	std::string hostStr = self.addr.node;
	std::vector<std::string> & TF = self.server.TrustedForwarders;
	if (std::find(TF.begin(), TF.end(), hostStr) != TF.end())
		self.remoteHost = std::string(value.begin(), value.end());
	else
		LOG4CXX_DEBUG(self.logger, boost::format("Ignoring X-Forwarded-For header from %s") % hostStr);
}

#define HEADER_METHOD2(s, n)  {"doHeader_" s, doHeader_ ## n},
#define HEADER_METHOD(n)  HEADER_METHOD2(#n, n)
static std::map<std::string, std::function<void(HTTPHandler&, bytes_t)> > headerMethods{
	HEADER_METHOD(accept_encoding)
	HEADER_METHOD(authorization)
	HEADER_METHOD(connection)
	HEADER_METHOD(content_length)
	HEADER_METHOD(x_forwarded_for)
	HEADER_METHOD2("accept-encoding", accept_encoding)
	HEADER_METHOD2("content-length", content_length)
	HEADER_METHOD2("x-forwarded-for", x_forwarded_for)
};

void HTTPHandler::doAuthenticate() {
	std::map<std::string, std::string> headers{
		{"WWW-Authenticate", (boost::format("Basic realm=\"%s\"") % server.ServerName).str()},
	};
	sendReply(401, NULL, headers);
}

void HTTPHandler::parse_headers(bytes_t hsb) {
	CL = -1;
	Username.clear();
	method.clear();
	path.clear();
	
	std::vector<bytes_t> hs;
	{
		static boost::regex newline("\r?\n");
		std::string hsin_str(hsb.begin(), hsb.end());
		std::vector<std::string> hs_strvec;
		boost::regex_split(std::back_inserter(hs_strvec), hsin_str, newline);
		for (auto it = hs_strvec.begin(); it != hs_strvec.end(); ++it)
			hs.push_back(bytes_t(it->begin(), it->end()));
	}
	
	std::vector<bytes_t> data;
	boost::split(data, hs.front(), boost::is_any_of(" "));
	hs.erase(hs.begin());
	
	if (!data.empty())
		method = data[0];
	if (data.size() > 1)
		path = data[1];
	else
	{
		close();
		return;
	}
	extensions.clear();
	reqinfo.clear();
	quirks = default_quirks;
	if (data.size() != 3 || data[2] != BYTES('H','T','T','P','/','1','.','1'))
		quirks["close"] = false;
	while (true)
	{
		bytes_t datab;
		if (!hs.empty())
		{
			datab = hs.front();
			hs.erase(hs.begin());
		}
		else
			break;
		
		std::vector<bytes_t> data;
		{
			auto it = std::find(datab.begin(), datab.end(), ':');
			bytes_t tmp(datab.begin(), it);
			boost::algorithm::trim(tmp);
			data.push_back(tmp);
			if (it != datab.end())
			{
				tmp = bytes_t(it, datab.end());
				boost::algorithm::trim(tmp);
				data.push_back(tmp);
			}
		}
		
		std::string method("doHeader_");
		{
			std::string tmp(data[0].begin(), data[0].end());
			boost::algorithm::to_lower(tmp);
			method += tmp;
		}
		if (headerMethods.count(method))
		{
			try
			{
				headerMethods[method](*this, data[1]);
			}
			catch (RequestAlreadyHandled)
			{
				// Ignore multiple errors and such
			}
		}
	}
}

void HTTPHandler::found_terminator() {
	if (reading_headers)
	{
		bytes_t inbuf = boost::algorithm::join(incoming, bytes_t());
		incoming.clear();
		
		while (true)
		{
			if (inbuf.empty())
				return;
			if (inbuf[0] != '\r' && inbuf[0] != '\n')
				break;
			inbuf.erase(inbuf.begin());
		}
		
		reading_headers = false;
		parse_headers(inbuf);
		if (CL)
		{
			set_terminator(CL);
			return;
		}
	}
	
	set_terminator();
	try
	{
		handle_request();
		throw RequestNotHandled();
	}
	catch (RequestHandled)
	{
		reset_request();
	}
	catch (AsyncRequest)
	{
	}
	catch (...)
	{
		//self.logger.error(traceback.format_exc())
	}
}

void HTTPHandler::handle_src_request() {
#if 0
	if _SourceFiles is None:
		return self.sendReply(404)
	# For AGPL compliance, allow direct downloads of source code
	p = self.path[5:]
	if p == b'':
		# List of files
		body = b'<html><head><title>Source Code</title></head><body>\t\n'
		body += b'\t<a href="tar">(tar archive of all files)</a><br><br>\n'
		for f in _SourceFiles:
			body += b'\t<a href="' + f + b'">\n' + f + b'\n\t</a><br>\n'
		body += b'\t</body></html>\n'
		return self.sendReply(body=body, headers={'Content-Type':'text/html'})
	if p == b'tar':
		body = bytearray()
		dn = b'ciloipoolpp-' + _GitDesc + b'/'
		for f in _SourceFiles:
			fs = f.decode('utf8')
			fstat = os.lstat(fs)
			islink = stat.S_ISLNK(fstat.st_mode)
			if islink:
				data = b''
				link = os.readlink(f)
			else:
				with open("%s/%s" % (_srcdir, fs), 'rb') as ff:
					data = ff.read()
				link = b''
			h = bytearray()
			f = dn + f
			h += f + bytes(max(0, 100 - len(f)))
			h += ('%07o' % (fstat.st_mode,)[-7:]).encode('utf8') + b'\0'
			h += bytes(16)
			h += ('%012o%012o' % (fstat.st_size, fstat.st_mtime)).encode('utf8')
			h += b'        '  # chksum
			h += b'2' if islink else b'0'
			h += link + bytes(max(0, 355 - len(link)))
			h[148:156] = ('%07o' % (sum(h),)).encode('utf8') + b'\0'
			body += h + data + bytes(512 - ((fstat.st_size % 512) or 512))
		self.sendReply(body=body, headers={'Content-Type':'application/x-tar'})
	if p not in _SourceFiles:
		return self.sendReply(404)
	ct = 'text/plain'
	if p[-3:] == b'.py': ct = 'application/x-python'
	elif p[-11:] == b'.py.example': ct = 'application/x-python'
	p = p.decode('utf8')
	with open("%s/%s" % (_srcdir, p), 'rb') as f:
		self.sendReply(body=f.read(), headers={'Content-Type':ct})
#endif
}

void HTTPHandler::reset_request() {
	replySent = false;
	incoming.clear();
	set_terminator(std::vector<bytes_t>{BYTES('\n', '\n'), BYTES('\r', '\n', '\r', '\n')});
	reading_headers = true;
	changeTask(std::bind(&HTTPHandler::handle_timeout, this), time(NULL) + 150);
	if (quirks.count("close"))
		close();
	// proxies can do multiple requests in one connection for multiple clients, so reset address every time
	remoteHost = addr.node;
}

HTTPHandler::HTTPHandler(networkserver::AsyncSocketServer & server, socket_t sock, networkserver::_SockAddr addr) :
	SocketHandler(server, sock, addr),
	quirks(default_quirks)
{
	logger = log4cxx::Logger::getLogger("HTTPHandler");
	reset_request();
}

};
