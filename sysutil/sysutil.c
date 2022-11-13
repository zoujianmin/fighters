/*
 * Copyright 2022 Ye Jiaqiang <yejq.jiaqiang@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/prctl.h>

#include <lua.h>
#include <lauxlib.h>
#include "apputil.h"

extern int luaopen_sysutil(lua_State * L);

static int sysutil_checkstack(lua_State * lua, int num)
{
	int ret;
	ret = lua_checkstack(lua, num);
	if (ret == 0) {
		fprintf(stderr, "Error, checkstack(%p, %d) has failed!\n",
			lua, num);
		fflush(stderr);
		return -1;
	}
	return 0;
}

static int sysutil_isinteger(lua_State * L,
	int num, lua_Integer * intp)
{
	int dtype;
	lua_Number num_l;
	lua_Integer int_l;

	dtype = lua_type(L, num);
	if (dtype != LUA_TNUMBER)
		return 0;

	num_l = lua_tonumber(L, num);
	int_l = lua_tointeger(L, num);
	if (num_l == (lua_Number) int_l) {
		if (intp != NULL)
			*intp = int_l;
		return 1;
	}
	return 0;
}

static int sysutil_uptime(lua_State * L)
{
	int ret;
	struct timespec uptim;

	ret = sysutil_checkstack(L, 2);
	if (ret < 0)
		return 0;

	ret = clock_gettime(CLOCK_BOOTTIME, &uptim);
	if (ret == -1)
		ret = clock_gettime(CLOCK_MONOTONIC, &uptim);
	if (ret == -1) {
		int error;
		error = errno;
		uptim.tv_sec = time(NULL);
		uptim.tv_nsec = 0;
		fprintf(stderr, "Error, failed to get system uptime: %s\n",
			strerror(error));
		fflush(stderr);
	}

	lua_pushinteger(L, (lua_Integer) uptim.tv_sec);
	lua_pushinteger(L, (lua_Integer) (uptim.tv_nsec / 1000000));
	return 2;
}

static int sysutil_common_delay(lua_State * L, int issec)
{
	long delaysec;
	int ret, error;
	int argc, nexti;
	lua_Integer luai;
	struct timespec delay;
	pthread_mutex_t * lockp;

	error = 0;
	nexti = 2;
	lockp = NULL;
	ret = sysutil_checkstack(L, 2);
	if (ret < 0)
		return 0;

	argc = lua_gettop(L);
	if (argc <= 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, no argument given to delay");
		return 2;
	}

	luai = 0;
	ret = sysutil_isinteger(L, 1, &luai);
	if (ret == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, delay is not an integer");
		return 2;
	}

	delaysec = (long) luai;
	if (delaysec <= 0) {
		int dsec = (int) delaysec;
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid delay in seconds: %d", dsec);
		return 2;
	}

	if (issec != 0) {
		delay.tv_sec = (time_t) delaysec;
		delay.tv_nsec = 0;
	} else {
		delay.tv_sec = (time_t) (delaysec / 1000);
		delay.tv_nsec = (delaysec % 1000) * 1000000;
	}

	if (argc >= 2 && lua_type(L, 2) == LUA_TBOOLEAN) {
		struct timespec nowt;
		if (delay.tv_sec > 0 && lua_toboolean(L, 2)) {
			nowt.tv_sec = 0;
			nowt.tv_nsec = 0;
			ret = clock_gettime(CLOCK_REALTIME, &nowt);
			if (ret == 0 && nowt.tv_nsec > 0) {
				delay.tv_sec -= 1;
				delay.tv_nsec = 1000000000 - nowt.tv_nsec;
			}
		}
		nexti++;
	}

	if (argc >= nexti && lua_type(L, nexti) == LUA_TSTRING) {
		const char * mlock;
		unsigned long lockptr = 0;
		mlock = lua_tolstring(L, nexti, NULL);
		if (mlock && mlock[0]) {
			errno = 0;
			lockptr = strtoul(mlock, NULL, 0);
			error = errno;
			if (error || lockptr == ULONG_MAX) {
				lockptr = 0;
				fprintf(stderr, "Error, invalid mutex pointer: %s\n", mlock);
				fflush(stderr);
			}
		}
		lockp = (pthread_mutex_t *) lockptr;
	}

	ret = lockp ? pthread_mutex_unlock(lockp) : 0;
	if (ret != 0) {
		fprintf(stderr, "Error, failed to release mutex %p: %d\n",
			lockp, ret);
		fflush(stderr);
		lua_pushnil(L);
		lua_pushstring(L, "Error, failed to release mutex.");
		return 2;
	}

	error = 0;
	ret = nanosleep(&delay, NULL);
	if (ret == -1)
		error = errno;

	ret = lockp ? pthread_mutex_lock(lockp) : 0;
	if (ret != 0) {
		fprintf(stderr, "Error, failed to acquire mutex %p: %d\n",
			lockp, ret);
		fflush(stderr);
		lua_pushnil(L);
		lua_pushstring(L, "Error, failed to acquire mutex.");
	}

	lua_pushinteger(L, error);
	return 1;
}

static int sysutil_delay(lua_State * L)
{
	return sysutil_common_delay(L, 1);
}

static int sysutil_mdelay(lua_State * L)
{
	return sysutil_common_delay(L, 0);
}

static int sysutil_call(lua_State * L)
{
	size_t inlen;
	apputil_t appu;
	const char * input;
	int options, dtype;
	int ret, ntop, error;

	inlen = 0;
	error = 0;
	input = NULL;
	ret = sysutil_checkstack(L, 4);
	if (ret < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 2) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid number of argument: %d", ntop);
		return 2;
	}

	dtype = lua_type(L, 2);
	if (sysutil_isinteger(L, 1, NULL) == 0 ||
		(dtype != LUA_TSTRING && dtype != LUA_TTABLE)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid type of argument: %d, %d",
			lua_type(L, 1), dtype);
		return 2;
	}

	options = (int) lua_tointeger(L, 1);
	appu = apputil_new(NULL, options);
	if (appu == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "System Out Of Memory!");
		return 2;
	}

	error = 0;
	if (dtype == LUA_TSTRING) {
		int idx;
		for (idx = 2; idx <= ntop; ++idx) {
			size_t arglen;
			const char * arg;
			if (lua_type(L, idx) != LUA_TSTRING)
				break;

			arglen = 0;
			arg = lua_tolstring(L, idx, &arglen);
			if (arg == NULL) {
				/* impossible scenario */
				fprintf(stderr, "Error, cannot fetch string at stack[%d]!\n", idx);
				fflush(stderr);
				continue;
			}
			ret = apputil_arg(appu, arg, arglen);
			if (ret < 0) {
				error = idx;
				fprintf(stderr, "Error, failed to insert argument '%s': %d\n", arg, ret);
				fflush(stderr);
				break;
			}
		}
	} else {
		int idx, newtop;
		newtop = lua_gettop(L);
		for (idx = 1; idx <= APPUTIL_MAXARGS; ++idx) {
			size_t arglen;
			const char * arg;

			lua_pushinteger(L, idx);
			lua_gettable(L, 2);
			if (lua_type(L, -1) != LUA_TSTRING) {
				lua_settop(L, newtop);
				break;
			}

			arglen = 0;
			arg = lua_tolstring(L, -1, &arglen);
			if (arg == NULL) {
				lua_settop(L, newtop);
				break;
			}

			ret = apputil_arg(appu, arg, arglen);
			lua_settop(L, newtop);
			if (ret < 0) {
				error = idx;
				fprintf(stderr, "Error, failed to insert argument '%s': %d\n", arg, ret);
				fflush(stderr);
				break;
			}
		}

		if (ntop >= 3 && lua_type(L, 3) == LUA_TSTRING)
			input = lua_tolstring(L, 3, &inlen);
	}

	if (error) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, failed process argument %d", error);
		apputil_free(appu);
		return 2;
	}

	ret = apputil_call(appu, input, (unsigned int) inlen);
	if (ret < 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, failed to call application");
		apputil_free(appu);
		return 2;
	}

	if (options & APPUTIL_OPTION_NOWAIT) {
		lua_pushinteger(L, (lua_Integer) apputil_getpid(appu, 1));
		lua_pushinteger(L, apputil_stdin(appu, 1));
		lua_pushinteger(L, apputil_stdout(appu, 1));
		apputil_free(appu);
		return 3;
	}

	ret = 1;
	lua_pushinteger(L, apputil_exitval(appu));
	if (options & APPUTIL_OPTION_OUTPUT) {
		char * output;
		unsigned int len, outlen;

		outlen = 0;
		len = (unsigned int) (options & APPUTIL_PIPE_MASK);
		if (len == 0)
			len = APPUTIL_BUFSIZE;
		output = apputil_read(appu, len, &outlen);
		if (output && outlen > 0) {
			lua_pushlstring(L, output, (size_t) outlen);
			ret++;
		}
		if (output != NULL)
			free(output);
	}
	apputil_free(appu);
	return ret;
}

static int sysutil_setname(lua_State * L)
{
	int ntop, ret;
	char thname[20];
	const char * tname = NULL;

	ntop = lua_gettop(L);
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		tname = lua_tolstring(L, 1, NULL);
	if (tname == NULL || tname[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid thread name string");
		return 2;
	}

	memset(thname, 0, sizeof(thname));
	strncpy(thname, tname, sizeof(thname) - 1);
	ret = prctl(PR_SET_NAME, (unsigned long) thname, 0, 0, 0);
	if (ret == -1) {
		int error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "prctl(SET_NAME, %s) has failed: %s",
			thname, strerror(error));
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int system_tcpsock(int * sockp, int ipv6)
{
	int error;
	int sockfd;

	sockfd = *sockp;
	if (sockfd != -1) {
		close(sockfd);
		*sockp = -1;
	}

	sockfd = socket(ipv6 ? AF_INET6 : AF_INET,
		SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockfd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to create TCP socket: %s\n",
			strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	appu_fdblock(sockfd, 0);
	*sockp = sockfd;
	return 0;
}

static int system_tcpconn(const char * ipaddr, int portno,
	const void * ipv4addr, const void * ipv6addr, int timeout)
{
	int sockfd;
	int ret, error;
	socklen_t socklen;
	struct sockaddr_in v4addr;
	struct sockaddr_in6 v6addr;

	error = 0;
	sockfd = -1;
	socklen = 0;
	memset(&v4addr, 0, sizeof(v4addr));
	v4addr.sin_family = AF_INET;
	v4addr.sin_port = htons((unsigned short) portno);

	memset(&v6addr, 0, sizeof(v6addr));
	v6addr.sin6_family = AF_INET6;
	v6addr.sin6_port = htons((unsigned short) portno);

	if (ipaddr != NULL) {
		if (inet_pton(AF_INET, ipaddr, (void *) &v4addr.sin_addr) == 1) {
			socklen = sizeof(v4addr);
			system_tcpsock(&sockfd, 0);
		} else if (inet_pton(AF_INET6, ipaddr, (void *) &v6addr.sin6_addr) == 1) {
			socklen = sizeof(v6addr);
			system_tcpsock(&sockfd, 1);
		} else {
			error = EADDRNOTAVAIL;
			goto err0;
		}
	}

	if (socklen)
		goto docon;

	if (ipv4addr != NULL) {
		const struct sockaddr_in * addrp;
		addrp = (const struct sockaddr_in *) ipv4addr;

		socklen = sizeof(v4addr);
		v4addr.sin_addr = addrp->sin_addr;
		system_tcpsock(&sockfd, 0);
	} else if (ipv6addr != NULL) {
		const struct sockaddr_in6 * addrp;
		addrp = (const struct sockaddr_in6 *) ipv6addr;

		socklen = sizeof(v6addr);
		v6addr.sin6_addr = addrp->sin6_addr;
		system_tcpsock(&sockfd, 1);
	} else {
		error = EADDRNOTAVAIL;
		goto err0;
	}

docon:
	if (sockfd == -1) {
		error = EBADF;
		goto err0;
	}

	do {
		const struct sockaddr * addrp;
		addrp = (const struct sockaddr *) &v4addr;
		if (socklen != sizeof(v4addr))
			addrp = (const struct sockaddr *) &v6addr;
		errno = 0;
		ret = connect(sockfd, addrp, socklen);
		error = errno;
	} while (0);

	if (ret == 0) {
		error = 0;
		goto err0;
	}

	if (error == ECONNREFUSED)
		goto err0;
	if (error == EINPROGRESS) {
		int err_n, serror;
		struct pollfd tfd;
again:
		tfd.fd = sockfd;
		tfd.events = POLLOUT | POLLERR | POLLPRI;
		tfd.revents = 0;

		errno = 0;
		ret = poll(&tfd, 1, timeout);
		if (ret == 0) {
			error = ETIMEDOUT;
			goto err0;
		}
		if (ret == -1) {
			err_n = errno;
			if (err_n == EINTR)
				goto again;

			fprintf(stderr, "Error, poll on TCP connect has failed: %s\n",
				strerror(err_n));
			fflush(stderr);
			error = err_n;
			goto err0;
		}

		serror = 0;
		socklen = sizeof(serror);
		ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &serror, &socklen);
		if (ret == -1) {
			err_n = errno;
			fprintf(stderr, "Error, failed to retrieve socket error: %s\n",
				strerror(err_n));
			fflush(stderr);
			error = err_n;
			goto err0;
		}
		error = serror;
	} else if (error != ENETUNREACH) {
		fprintf(stderr, "Error, TCP connect has failed: %s\n",
			strerror(error));
		fflush(stderr);
	}

err0:
	if (sockfd != -1)
		close(sockfd);
	return error;
}

static int sysutil_tcpcheck(lua_State * L)
{
	lua_Integer luai;
	const char * hostip;
	struct addrinfo * i_info;
	struct addrinfo * a_info;
	int ntop, timeo, portn, rval;

	luai = 0;
	rval = 0;
	timeo = 2500; /* 2500 milliseconds */
	i_info = a_info = NULL;
	if (sysutil_checkstack(L, 3) < 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 2 || lua_type(L, 1) != LUA_TSTRING ||
		sysutil_isinteger(L, 2, &luai) == 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid type of arguments: %d, %d",
			lua_type(L, 1), lua_type(L, 2));
		return 2;
	}

	portn = (int) luai;
	hostip = lua_tolstring(L, 1, NULL);
	if (hostip == NULL || hostip[0] == '\0' || portn <= 0 || portn >= 0xFFFF) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid host-ip or port-number: %d", portn);
		return 2;
	}

	luai = 0;
	if (ntop >= 3 && sysutil_isinteger(L, 3, &luai))
		timeo = (int) luai;

	rval = system_tcpconn(hostip, portn, NULL, NULL, timeo);
	if (rval != EADDRNOTAVAIL) {
		lua_pushinteger(L, rval);
		return 1;
	}

	a_info = NULL;
	rval = getaddrinfo(hostip, NULL, NULL, &a_info);
	if (rval != 0) {
		if (a_info != NULL) {
			freeaddrinfo(a_info);
			a_info = NULL;
		}
		lua_pushinteger(L, rval);
		return 1;
	}

	rval = EADDRNOTAVAIL;
	for (i_info = a_info; i_info != NULL; i_info = i_info->ai_next) {
		int error;
		if (i_info->ai_addrlen == sizeof(struct sockaddr_in)) {
			error = system_tcpconn(NULL, portn, i_info->ai_addr, NULL, timeo);
			rval = error;
			if (error == 0 || error == ECONNREFUSED)
				break;
		} else if (i_info->ai_addrlen == sizeof(struct sockaddr_in6)) {
			error = system_tcpconn(NULL, portn, NULL, i_info->ai_addr, timeo);
			rval = error;
			if (error == 0 || error == ECONNREFUSED)
				break;
		} else {
			rval = EADDRNOTAVAIL;
			fprintf(stderr, "Error, invalid ipaddr length: %d\n",
				(int) i_info->ai_addrlen);
			fflush(stderr);
		}
	}

	if (a_info != NULL) {
		freeaddrinfo(a_info);
		a_info = NULL;
	}
	lua_pushinteger(L, rval);
	return 1;
}

static const luaL_Reg sysutil_regs[] = {
	{ "call",           sysutil_call },
	{ "delay",          sysutil_delay },
	{ "mdelay",         sysutil_mdelay },
	{ "setname",        sysutil_setname },
	{ "tcpcheck",       sysutil_tcpcheck },
	{ "uptime",         sysutil_uptime },
	{ NULL,             NULL },
};

int luaopen_sysutil(lua_State * L)
{
	luaL_register(L, "sysutil", sysutil_regs);

	lua_pushinteger(L, APPUTIL_OPTION_NULLIO);
	lua_setfield(L, -2, "OPT_NULLIO");

	lua_pushinteger(L, APPUTIL_OPTION_INPUT);
	lua_setfield(L, -2, "OPT_INPUT");

	lua_pushinteger(L, APPUTIL_OPTION_OUTPUT);
	lua_setfield(L, -2, "OPT_OUTPUT");

	lua_pushinteger(L, APPUTIL_OPTION_OUTALL);
	lua_setfield(L, -2, "OPT_OUTALL");

	lua_pushinteger(L, APPUTIL_OPTION_NOWAIT);
	lua_setfield(L, -2, "OPT_NOWAIT");

	lua_pushinteger(L, APPUTIL_OPTION_CLOSEFDS);
	lua_setfield(L, -2, "OPT_CLOSEFDS");

	lua_pushinteger(L, APPUTIL_OPTION_LOWPRI);
	lua_setfield(L, -2, "OPT_LOWPRI");
	return 1;
}
