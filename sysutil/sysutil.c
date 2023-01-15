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
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/prctl.h>
#ifndef __GLIBC__
  /* for syscall(...), gettid */
  #include <sys/syscall.h>
#endif

#include <lua.h>
#include <lauxlib.h>
#include "apputil.h"
#include "zsha256_util.h"

#include <glob.h> /* request for glob function */

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
		fprintf(stderr, "Error, failed to get system uptime: %s\n",
			strerror(error));
		fflush(stderr);
		errno = error;
		return 0;
	}

	lua_pushinteger(L, (lua_Integer) uptim.tv_sec);
	lua_pushinteger(L, (lua_Integer) (uptim.tv_nsec / 1000000));
	return 2;
}

static int sysutil_common_delay(lua_State * L, int issec)
{
	int ret, error;
	int argc, nexti;
	lua_Integer luai;
	long long delaysec;
	struct timespec delay;
	pthread_mutex_t * lockp;

	error = 0;
	nexti = 2;
	lockp = NULL;
	delaysec = -1;
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
		if (lua_type(L, 1) != LUA_TNUMBER) {
			lua_pushnil(L);
			lua_pushstring(L, "Error, delay is not an integer");
			return 2;
		}
		delaysec = (long long) lua_tonumber(L, 1);
	} else
		delaysec = (long long) luai;

	if (delaysec == 0) {
		lua_pushinteger(L, 0);
		return 1;
	}

	if (delaysec < 0) {
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
		delay.tv_nsec = (long) ((delaysec % 1000) * 1000000);
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
	if (options & (APPUTIL_OPTION_OUTPUT | APPUTIL_OPTION_OUTALL)) {
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

	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
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
		SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
	if (sockfd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to create TCP socket: %s\n",
			strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

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

static int sysutil_mountpoint(lua_State * L)
{
	int ntop;
	size_t mlen;
	const char * mpath;

	if (sysutil_checkstack(L, 2) < 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop <= 0 || lua_type(L, 1) != LUA_TSTRING) {
err0:
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument for mountpoint");
		return 2;
	}

	mlen = 0;
	mpath = lua_tolstring(L, 1, &mlen);
	if (mpath == NULL || mlen == 0)
		goto err0;
	lua_pushboolean(L, appf_mountpoint(mpath) == 0);
	return 1;
}

static int sysutil_read(lua_State * L)
{
	ssize_t rl1;
	lua_Integer luai;
	size_t flen, maxlen;
	unsigned char * fild;
	int ntop, fd, isfile;

	fd = -1;
	flen = 0;
	luai = 0;
	isfile = 0;
	fild = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 1) {
		lua_pushnil(L);
		lua_pushstring(L, "no valid argument given");
		return 2;
	}

	if (lua_type(L, 1) == LUA_TSTRING) {
		const char * filp;
		filp = lua_tolstring(L, 1, NULL);
		if (filp == NULL || filp[0] == '\0') {
			lua_pushnil(L);
			lua_pushstring(L, "invalid path of file to read");
			return 2;
		}

		isfile = -1;
		fd = open(filp, O_RDONLY | O_CLOEXEC);
		if (fd == -1) {
			int error = errno;
			lua_pushnil(L);
			lua_pushfstring(L, "failed to open '%s': %s\n",
				filp, strerror(error));
			return 2;
		}
	} else if (sysutil_isinteger(L, 1, &luai)) {
		isfile = 0;
		fd = (int) luai;
	}

	if (fd < 0) {
		lua_pushnil(L);
		lua_pushstring(L, "not a valid file descriptor");
		return 2;
	}

	luai = 0;
	if (ntop >= 2 && sysutil_isinteger(L, 2, &luai)) {
		flen = (size_t) luai;
	} else if (isfile) {
		struct stat fst;
		if (fstat(fd, &fst) == 0)
			flen = (size_t) fst.st_size;
	}

	luai = 0;
	maxlen = 256 * 1024 * 1024; /* 256MB */
	if (flen >= 3 && sysutil_isinteger(L, 3, &luai))
		maxlen = (size_t) luai;
	if (flen > maxlen)
		flen = maxlen;

	/* should not read zero length of data */
	if (flen == 0)
		flen = APPUTIL_BUFSIZE;

	fild = (unsigned char *) malloc(flen);
	if (fild == NULL) {
		if (isfile)
			close(fd);
		lua_pushnil(L);
		lua_pushstring(L, "system out of memory");
		return 2;
	}

	rl1 = read(fd, fild, flen);
	if (rl1 <= 0) {
		int error = errno;
		if (isfile)
			close(fd);
		free(fild);
		lua_pushnil(L);
		lua_pushfstring(L, "failed to read from %d: %s\n",
			fd, strerror(error));
		return 2;
	}

	if (isfile)
		close(fd);
	lua_pushlstring(L, (const char *) fild, (size_t) rl1);
	free(fild);
	return 1;
}

static int sysutil_waitpid(lua_State * L)
{
	pid_t pid, pid1;
	lua_Integer luai;
	int ntop, nohang, est;

	pid = 0;
	nohang = 0;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	luai = 0;
	ntop = lua_gettop(L);
	if (ntop >= 1 && sysutil_isinteger(L, 1, &luai))
		pid = (pid_t) luai;
	if (pid <= 0l) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid PID given to waitpid");
		return 2;
	}

	if (ntop >= 2 &&
		lua_type(L, 2) == LUA_TBOOLEAN &&
		lua_toboolean(L, 2))
		nohang = WNOHANG;

again:
	est = 0;
	pid1 = waitpid(pid, &est, nohang);
	if (pid1 < 0) {
		int error = errno;
		if (error == EINTR && nohang == 0)
			goto again;
		lua_pushnil(L);
		lua_pushfstring(L, "failed to waitpid '%d': %s",
			(int) pid, strerror(error));
		return 2;
	}

	if (pid1 == pid) {
		/* child process not running */
		lua_pushboolean(L, 0);
		lua_pushinteger(L, est);
		return 2;
	}

	/* child process happily running */
	lua_pushboolean(L, 1);
	return 1;
}

#define SYSUTIL_KILL       0
#define SYSUTIL_KILLID     1
#define SYSUTIL_KILLPG     2

static int sysutil_kill_common(lua_State * L, int istid)
{
	lua_Integer pid;
	lua_Integer luai;
	const char * fname;
	int ntop, signo, error;

	pid = 0;
	error = 0;
	signo = 0;
	fname = "unknown";
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 1 || sysutil_isinteger(L, 1, &pid) == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "PID not given for killing");
		return 2;
	}

	luai = 0;
	if (ntop >= 2 && sysutil_isinteger(L, 2, &luai))
		signo = (int) luai;
	switch (istid) {
	case SYSUTIL_KILL:
		fname = "kill";
		if (kill((pid_t) pid, signo) == -1)
			error = errno;
		break;

	case SYSUTIL_KILLID:
		fname = "pthread_kill";
		error = pthread_kill((pthread_t) pid, signo);
		break;

	case SYSUTIL_KILLPG:
		fname = "killpg";
		if (killpg((pid_t) pid, signo) == -1)
			error = errno;
		break;

	default:
		break;
	}

	if (error != 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "%s(%d, %d) has failed: %s",
			fname, (int) pid, signo, strerror(error));
		return 2;
	}
	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_kill(lua_State * L)
{
	return sysutil_kill_common(L, SYSUTIL_KILL);
}

static int sysutil_sha256(lua_State * L)
{
	size_t flen;
	int ntop, isfile;
	const char * filp;
	struct zsha256 sha256;

	flen = 0;
	filp = NULL;
	isfile = 0;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		filp = lua_tolstring(L, 1, &flen);
	if (ntop >= 2 && lua_type(L, 2) == LUA_TBOOLEAN)
		isfile = lua_toboolean(L, 2);

	if (isfile && (filp == NULL || flen == 0)) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument for sha256");
		return 2;
	}

	zsha256_init(&sha256);
	if (isfile) {
		int fd, error;
		unsigned char * bufp;
		const size_t rsize = 1024 * 1024;

		fd = open(filp, O_RDONLY | O_CLOEXEC);
		if (fd == -1) {
			error = errno;
			lua_pushnil(L);
			lua_pushfstring(L, "Error, failed to open(%s): %s",
				filp, strerror(error));
			return 2;
		}

		bufp = (unsigned char *) malloc(rsize);
		if (bufp == NULL) {
			close(fd);
			lua_pushnil(L);
			lua_pushstring(L, "System out of memory");
			return 2;
		}

		for (;;) {
			size_t rl1;
			rl1 = read(fd, bufp, rsize);
			if (rl1 < 0) {
				error = errno;
				if (error == EINTR)
					continue;
				fprintf(stderr, "Error, failed to read %s: %s\n",
					filp, strerror(error));
				fflush(stderr);
				break;
			}

			if (rl1 == 0)
				break;
			zsha256_update(&sha256, bufp, (unsigned int) rl1);
			if (rl1 != (ssize_t) rsize)
				break;
		}

		close(fd);
		free(bufp);
	} else {
		zsha256_update(&sha256,
			(const unsigned char *) filp, (unsigned int) flen);
	}

	zsha256_final(&sha256, NULL, 0);
	if (ntop >= 3 &&
		lua_type(L, 3) == LUA_TBOOLEAN &&
		lua_toboolean(L, 3)) {
		char out[ZSHA256_STRSIZE];
		memset(out, 0, sizeof(out));
		zsha256_hex(out, sizeof(out), &sha256);
		lua_pushstring(L, out);
		return 1;
	}

	lua_pushlstring(L, (const char *) sha256.hashval, 32);
	return 1;
}

static int sysutil_zipstdio(lua_State * L)
{
	int ntop;
	const char * pdev;

	pdev = NULL;
	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING) {
		pdev = lua_tolstring(L, 1, NULL);
		if (pdev && pdev[0] == '\0')
			pdev = NULL;
	}
	lua_pushboolean(L, appf_zipstdio(pdev, 0) == 0);
	return 1;
}

static int sysutil_getpid(lua_State * L)
{
	pid_t pid;
	if (sysutil_checkstack(L, 1) < 0)
		return 0;
	pid = getpid();
	lua_pushinteger(L, (lua_Integer) pid);
	return 1;
}

static int sysutil_getppid(lua_State * L)
{
	pid_t pid;
	if (sysutil_checkstack(L, 1) < 0)
		return 0;
	pid = getppid();
	lua_pushinteger(L, (lua_Integer) pid);
	return 1;
}

static int sysutil_gettid(lua_State * L)
{
	long pid;
	if (sysutil_checkstack(L, 1) < 0)
		return 0;
#ifdef __GLIBC__
	pid = (long) gettid();
#else
	pid = syscall(SYS_gettid, 0);
#endif
	lua_pushinteger(L, (lua_Integer) pid);
	return 1;
}

static int sysutil_getid(lua_State * L)
{
	pthread_t tid;
	if (sysutil_checkstack(L, 1) < 0)
		return 0;
	tid = pthread_self();
	lua_pushinteger(L, (lua_Integer) tid);
	return 1;
}

static int sysutil_killid(lua_State * L)
{
	return sysutil_kill_common(L, SYSUTIL_KILLID);
}

static int sysutil_killpg(lua_State * L)
{
	return sysutil_kill_common(L, SYSUTIL_KILLPG);
}

static int sysutil_readlink(lua_State * L)
{
	int ntop;
	ssize_t rl1;
	char * output;
	const char * linkp;

	linkp = NULL;
	output = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		linkp = lua_tolstring(L, 1, NULL);

	if (linkp == NULL || linkp[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument to readlink");
		return 2;
	}

	output = (char *) malloc(APPUTIL_BUFSIZE);
	if (output == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "system out of memory for readlink");
		return 2;
	}

	rl1 = readlink(linkp, output, APPUTIL_BUFSIZE);
	if (rl1 < 0) {
		int error;
		error = errno;
		free(output);
		lua_pushnil(L);
		lua_pushfstring(L, "readlink(%s) has failed: %s",
			linkp, strerror(error));
		errno = error;
		return 2;
	}

	if (rl1 > APPUTIL_BUFSIZE)
		rl1 = APPUTIL_BUFSIZE;
	lua_pushlstring(L, output, (size_t) rl1);
	free(output);
	return 1;
}

static int sysutil_unlink(lua_State * L)
{
	int idx, jdx;
	int ntop, error;

	jdx = 0;
	error = 0;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	for (idx = 1; idx <= ntop; ++idx) {
		const char * filp;
		if (lua_type(L, idx) != LUA_TSTRING)
			continue;

		filp = lua_tolstring(L, idx, NULL);
		if (filp == NULL || filp[0] == '\0')
			continue;

		if (unlink(filp) == -1)
			error++;
		else
			jdx++;
	}

	lua_pushinteger(L, jdx);
	lua_pushinteger(L, error);
	return 2;
}

static int sysutil_rmdir(lua_State * L)
{
	int idx, jdx;
	int error, ntop;

	jdx = 0;
	error = 0;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	for (idx = 1; idx <= ntop; ++idx) {
		const char * dirp;
		if (lua_type(L, idx) != LUA_TSTRING)
			continue;

		dirp = lua_tolstring(L, 1, NULL);
		if (dirp == NULL || dirp[0] == '\0')
			continue;

		if (rmdir(dirp) == -1)
			error++;
		else
			jdx++;
	}

	lua_pushinteger(L, jdx);
	lua_pushinteger(L, error);
	return 2;
}

static int sysutil_mkdir(lua_State * L)
{
	mode_t dirm;
	int ret, ntop;
	lua_Integer mode;
	const char * dirp;

	dirp = NULL;
	dirm = 0755;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		dirp = lua_tolstring(L, 1, NULL);

	if (dirp == NULL || dirp[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument to mkdir");
		return 2;
	}

	mode = 0;
	if (ntop >= 2 && sysutil_isinteger(L, 2, &mode))
		dirm = (mode_t) mode;

	ret = mkdir(dirp, dirm);
	if (ret < 0) {
		int error;
		error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "mkdir(%s) has failed: %s",
			dirp, strerror(error));
		errno = error;
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_stat(lua_State * L)
{
	struct stat fst;
	const char * filp;
	int error, ntop, issym;

	issym = 0;
	filp = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		filp = lua_tolstring(L, 1, NULL);
	if (filp == NULL || filp[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument for stat");
		return 2;
	}

	if (ntop >= 2 && lua_type(L, 2) == LUA_TBOOLEAN)
		issym = lua_toboolean(L, 2);

	memset(&fst, 0, sizeof(fst));
	error = issym ? lstat(filp, &fst) : stat(filp, &fst);
	if (error == -1) {
		error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "stat(%s) has failed: %s",
			filp, strerror(error));
		errno = error;
		return 2;
	}

	lua_createtable(L, 0, 20);

	lua_pushinteger(L, (lua_Integer) fst.st_dev);
	lua_setfield(L, -2, "st_dev");

	lua_pushinteger(L, (lua_Integer) fst.st_ino);
	lua_setfield(L, -2, "st_ino");

	lua_pushinteger(L, (lua_Integer) fst.st_mode);
	lua_setfield(L, -2, "st_mode");

	lua_pushinteger(L, (lua_Integer) fst.st_nlink);
	lua_setfield(L, -2, "st_nlink");

	lua_pushinteger(L, (lua_Integer) fst.st_uid);
	lua_setfield(L, -2, "st_uid");

	lua_pushinteger(L, (lua_Integer) fst.st_gid);
	lua_setfield(L, -2, "st_gid");

	lua_pushinteger(L, (lua_Integer) fst.st_rdev);
	lua_setfield(L, -2, "st_rdev");

	lua_pushinteger(L, (lua_Integer) fst.st_size);
	lua_setfield(L, -2, "st_size");

	lua_pushinteger(L, (lua_Integer) fst.st_blksize);
	lua_setfield(L, -2, "st_blksize");

	lua_pushinteger(L, (lua_Integer) fst.st_blocks);
	lua_setfield(L, -2, "st_blocks");

	lua_pushinteger(L, (lua_Integer) fst.st_atime);
	lua_setfield(L, -2, "st_atime");

	lua_pushinteger(L, (lua_Integer) fst.st_mtime);
	lua_setfield(L, -2, "st_mtime");

	lua_pushinteger(L, (lua_Integer) fst.st_ctime);
	lua_setfield(L, -2, "st_ctime");

	lua_pushboolean(L, S_ISREG(fst.st_mode) != 0);
	lua_setfield(L, -2, "isreg");

	lua_pushboolean(L, S_ISDIR(fst.st_mode) != 0);
	lua_setfield(L, -2, "isdir");

	lua_pushboolean(L, S_ISLNK(fst.st_mode) != 0);
	lua_setfield(L, -2, "issym");

	lua_pushboolean(L, S_ISCHR(fst.st_mode) != 0);
	lua_setfield(L, -2, "ischr");

	lua_pushboolean(L, S_ISBLK(fst.st_mode) != 0);
	lua_setfield(L, -2, "isblk");

	lua_pushboolean(L, S_ISFIFO(fst.st_mode) != 0);
	lua_setfield(L, -2, "isfifo");

	lua_pushboolean(L, S_ISSOCK(fst.st_mode) != 0);
	lua_setfield(L, -2, "issock");
	return 1;
}

static int sysutil_glob(lua_State * L)
{
	glob_t gt;
	lua_Integer luai;
	int flags, ntop, ret;
	const char * pattern;

	luai = 0;
	flags = 0;
	pattern = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && sysutil_isinteger(L, 1, &luai))
		flags = (int) luai;
	if (ntop >= 2 && lua_type(L, 2) == LUA_TSTRING)
		pattern = lua_tolstring(L, 2, NULL);
	if (pattern == NULL || pattern[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "Error, invalid pattern for glob");
		return 2;
	}

	memset(&gt, 0, sizeof(gt));
	ret = glob(pattern, flags, NULL, &gt);
	lua_pushinteger(L, ret);
	if (gt.gl_pathc > 0 && gt.gl_pathv != NULL) {
		size_t idx;
		int jdx = 0;

		ntop = lua_gettop(L);
		lua_createtable(L, (int) (gt.gl_pathc + 1), 0);
		for (idx = 0; idx < gt.gl_pathc; ++idx) {
			const char * pathv = gt.gl_pathv[idx];
			if (pathv && pathv[0]) {
				lua_pushinteger(L, ++jdx);
				lua_pushstring(L, pathv);
				lua_settable(L, -3);
			}
		}

		globfree(&gt);
		if (jdx == 0) {
			lua_settop(L, ntop);
			return 1;
		}
		return 2;
	}

	globfree(&gt);
	return 1;
}

static int sysutil_chdir(lua_State * L)
{
	int ntop, error;
	const char * newdir;

	error = 0;
	newdir = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		newdir = lua_tolstring(L, 1, NULL);

	if (newdir && newdir[0]) {
		error = chdir(newdir);
		if (error == -1) {
			error = errno;
			lua_pushnil(L);
			lua_pushfstring(L, "chdir(%s) has failed: %s",
				newdir, strerror(error));
			return 2;
		}
		lua_pushboolean(L, 1);
		return 1;
	} else {
		char * curdir, * cdir;
		curdir = (char *) calloc(0x1, APPUTIL_BUFSIZE);
		if (curdir == NULL) {
			lua_pushnil(L);
			lua_pushstring(L, "System out of memory!");
			return 2;
		}

		cdir = getcwd(curdir, APPUTIL_BUFSIZE - 1);
		if (cdir == NULL) {
			error = errno;
			free(curdir);
			lua_pushnil(L);
			lua_pushfstring(L, "getcwd() has failed: %s",
				strerror(error));
			return 2;
		}

		lua_pushstring(L, cdir);
		free(curdir);
		return 1;
	}
}

static int sysutil_sync(lua_State * L)
{
	int fd;
	lua_Integer luai;

	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	luai = -1;
	fd = lua_gettop(L);
	if (fd >= 1 && sysutil_isinteger(L, 1, &luai)) {
		fd = (int) luai;
		fd = syncfs(fd);
		if (fd == -1) {
			fd = errno;
			lua_pushboolean(L, 0);
			lua_pushinteger(L, fd);
			return 2;
		}
	} else {
		sync();
	}
	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_symlink(lua_State * L)
{
	int ntop, error;
	const char * src;
	const char * dst;

	error = 0;
	src = dst = NULL;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 2 ||
		lua_type(L, 1) != LUA_TSTRING ||
		lua_type(L, 2) != LUA_TSTRING) {
err0:
		lua_pushnil(L);
		lua_pushstring(L, "invalid arguments for symlink");
		return 2;
	}

	src = lua_tolstring(L, 1, NULL);
	dst = lua_tolstring(L, 2, NULL);
	if (src == NULL || src[0] == '\0' ||
		dst == NULL || dst[0] == '\0')
		goto err0;

	if (ntop >= 3 &&
		lua_type(L, 3) == LUA_TBOOLEAN &&
		lua_toboolean(L, 3))
		error = link(src, dst);
	else
		error = symlink(src, dst);
	if (error == -1) {
		error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "link/symlink(%s, %s) has failed: %s",
			src, dst, strerror(error));
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_mkfifo(lua_State * L)
{
	mode_t fifom;
	int ret, ntop;
	lua_Integer mode;
	const char * fifop;

	fifop = NULL;
	fifom = 0755;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		fifop = lua_tolstring(L, 1, NULL);

	if (fifop == NULL || fifop[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument to mkfifo");
		return 2;
	}

	mode = 0;
	if (ntop >= 2 && sysutil_isinteger(L, 2, &mode))
		fifom = (mode_t) mode;

	ret = mkfifo(fifop, fifom);
	if (ret < 0) {
		int error;
		error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "mkfifo(%s) has failed: %s",
			fifop, strerror(error));
		errno = error;
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_chmod(lua_State * L)
{
	mode_t mode;
	int ntop, ret;
	lua_Integer luai;

	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	luai = 0;
	ntop = lua_gettop(L);
	if (ntop < 2 || sysutil_isinteger(L, 2, &luai) == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid mode given to chmod");
		return 2;
	}

	mode = (mode_t) luai;
	luai = 0;
	if (sysutil_isinteger(L, 1, &luai)) {
		int pfd = (int) luai;
		ret = fchmod(pfd, mode);
		if (ret == -1) {
			int error;
			error = errno;
			lua_pushnil(L);
			lua_pushfstring(L, "fchmod(%d) has failed: %s",
				pfd, strerror(error));
			errno = error;
			return 2;
		}
	} else if (lua_type(L, 1) == LUA_TSTRING) {
		const char * filp;
		filp = lua_tolstring(L, 1, NULL);
		if (filp == NULL || filp[0] == '\0') {
			lua_pushnil(L);
			lua_pushstring(L, "invalid file path given to chmod");
			return 2;
		}
		ret = chmod(filp, mode);
		if (ret == -1) {
			int error;
			error = errno;
			lua_pushnil(L);
			lua_pushfstring(L, "chmod(%s) has failed: %s",
				filp, strerror(error));
			errno = error;
			return 2;
		}
	} else {
		lua_pushnil(L);
		lua_pushstring(L, "invalid argument given to chmod");
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int sysutil_upmsec(lua_State * L)
{
	int ret;
	struct timespec nowt;
	unsigned long long res;

	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	nowt.tv_sec = 0;
	nowt.tv_nsec = 0;
	ret = clock_gettime(CLOCK_BOOTTIME, &nowt);
	if (ret == -1) {
		ret = clock_gettime(CLOCK_MONOTONIC, &nowt);
		if (ret == -1) {
			int error = errno;
			fprintf(stderr, "Error, failed to determine system uptime: %s\n",
				strerror(error));
			fflush(stderr);
			errno = error;
			return 0;
		}
	}

	res = (unsigned long long) nowt.tv_sec;
	res = res * 1000 + (unsigned long long) (nowt.tv_nsec / 1000000);
#if LUA_VERSION_NUM < 503
	lua_pushnumber(L, (lua_Number) res);
#else
	lua_pushinteger(L, (lua_Integer) res);
#endif
	return 1;
}

static int sysutil_close(lua_State * L)
{
	int ntop, idx;
	int number, error;

	number = error = 0;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	ntop = lua_gettop(L);
	for (idx = 1; idx <= ntop; ++idx) {
		int fd = -1;
		if (lua_type(L, idx) == LUA_TNUMBER)
			fd = lua_tointeger(L, idx);
		if (fd >= 0) {
			if (close(fd) == 0)
				number++;
			else
				error++;
		}
	}

	lua_pushinteger(L, number);
	lua_pushinteger(L, error);
	return 2;
}

static int sysutil_cloexec(lua_State * L)
{
	lua_Integer luai;
	int ntop, fd, cloexec;

	fd = -1;
	cloexec = 1;
	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	luai = 0;
	ntop = lua_gettop(L);
	if (ntop >= 1 && sysutil_isinteger(L, 1, &luai))
		fd = (int) luai;
	if (ntop >= 2 && lua_type(L, 2) == LUA_TBOOLEAN)
		cloexec = lua_toboolean(L, 2);

	ntop = fcntl(fd, F_GETFD, 0);
	if (ntop == -1) {
		ntop = errno;
		lua_pushinteger(L, ntop);
		return 1;
	}

	if (cloexec != 0)
		cloexec = ntop | FD_CLOEXEC;
	else
		cloexec = ntop & ~FD_CLOEXEC;
	if (ntop == cloexec) {
		lua_pushinteger(L, 0);
		return 1;
	}

	if (fcntl(fd, F_SETFD, cloexec) == -1) {
		ntop = errno;
		lua_pushinteger(L, ntop);
		return 1;
	}
	lua_pushinteger(L, 0);
	return 1;
}

static int sysutil_open(lua_State * L)
{
	mode_t film;
	lua_Integer luai;
	const char * filp;
	int fd, ntop, flags;

	fd = -1;
	filp = NULL;
	film = (mode_t) 0644;
	flags = O_RDONLY | O_CLOEXEC;

	if (sysutil_checkstack(L, 2) < 0)
		return 0;

	luai = 0;
	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		filp = lua_tolstring(L, 1, NULL);
	if (filp == NULL || filp[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "Error, invalid argument for method open");
		return 2;
	}

	if (ntop >= 2 && sysutil_isinteger(L, 2, &luai))
		flags = (int) luai;
	if (ntop >= 3 && sysutil_isinteger(L, 3, &luai))
		film = (mode_t) luai;

	fd = open(filp, flags, film);
	if (fd == -1) {
		fd = errno;
		lua_pushnil(L);
		lua_pushinteger(L, fd);
		return 2;
	}

	lua_pushinteger(L, fd);
	return 1;
}

static const luaL_Reg sysutil_regs[] = {
	{ "call",           sysutil_call },
	{ "chdir",          sysutil_chdir },
	{ "chmod",          sysutil_chmod },
	{ "cloexec",        sysutil_cloexec },
	{ "close",          sysutil_close },
	{ "delay",          sysutil_delay },
	{ "getid",          sysutil_getid },       /* calls pthread_self() */
	{ "getpid",         sysutil_getpid },
	{ "getppid",        sysutil_getppid },
	{ "gettid",         sysutil_gettid },
	{ "glob",           sysutil_glob },
	{ "kill",           sysutil_kill },
	{ "killid",         sysutil_killid },      /* calls pthread_kill(...) */
	{ "killpg",         sysutil_killpg },
	{ "mdelay",         sysutil_mdelay },
	{ "mkdir",          sysutil_mkdir },
	{ "mkfifo",         sysutil_mkfifo },
	{ "mountpoint",     sysutil_mountpoint },
	{ "open",           sysutil_open },
	{ "read",           sysutil_read },
	{ "readlink",       sysutil_readlink },
	{ "rmdir",          sysutil_rmdir },
	{ "setname",        sysutil_setname },
	{ "sha256",         sysutil_sha256 },
	{ "stat",           sysutil_stat },
	{ "symlink",        sysutil_symlink },
	{ "sync",           sysutil_sync },
	{ "tcpcheck",       sysutil_tcpcheck },
	{ "unlink",         sysutil_unlink },
	{ "upmsec",         sysutil_upmsec },
	{ "uptime",         sysutil_uptime },
	{ "waitpid",        sysutil_waitpid },
	{ "zipstdio",       sysutil_zipstdio },
	{ NULL,             NULL },
};

#define SYSUTIL_PUSHINT(VAL_INT_) \
	do { \
		lua_Integer luai; \
		const char * valn = # VAL_INT_; \
		luai = (lua_Integer) VAL_INT_; \
		lua_pushinteger(L, luai); \
		lua_setfield(L, -2, valn); \
	} while (0)

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

	lua_pushinteger(L, APPUTIL_OPTION_CLOSER);
	lua_setfield(L, -2, "OPT_CLOSER");

	lua_pushinteger(L, APPUTIL_OPTION_LOWPRI);
	lua_setfield(L, -2, "OPT_LOWPRI");

	lua_pushinteger(L, APPUTIL_OPTION_SYMLINK);
	lua_setfield(L, -2, "OPT_SYMLINK");

	/* flags for glob(...) function: */
	SYSUTIL_PUSHINT(GLOB_ERR);
	SYSUTIL_PUSHINT(GLOB_MARK);
	SYSUTIL_PUSHINT(GLOB_NOSORT);
	SYSUTIL_PUSHINT(GLOB_NOCHECK);
	SYSUTIL_PUSHINT(GLOB_APPEND);
	SYSUTIL_PUSHINT(GLOB_NOESCAPE);
	SYSUTIL_PUSHINT(GLOB_PERIOD);
#ifdef GLOB_BRACE
	SYSUTIL_PUSHINT(GLOB_BRACE);
#endif
#ifdef GLOB_NOMAGIC
	SYSUTIL_PUSHINT(GLOB_NOMAGIC);
#endif
	SYSUTIL_PUSHINT(GLOB_ONLYDIR);

	/* flags for open function: */
	SYSUTIL_PUSHINT(O_RDONLY);
	SYSUTIL_PUSHINT(O_WRONLY);
	SYSUTIL_PUSHINT(O_RDWR);
	SYSUTIL_PUSHINT(O_APPEND);
	SYSUTIL_PUSHINT(O_CLOEXEC);
	SYSUTIL_PUSHINT(O_CREAT);
	SYSUTIL_PUSHINT(O_EXCL);
	SYSUTIL_PUSHINT(O_LARGEFILE);
	SYSUTIL_PUSHINT(O_NOATIME);
	SYSUTIL_PUSHINT(O_NOCTTY);
	SYSUTIL_PUSHINT(O_NOFOLLOW);
	SYSUTIL_PUSHINT(O_NONBLOCK);
	SYSUTIL_PUSHINT(O_TMPFILE);
	SYSUTIL_PUSHINT(O_TRUNC);

	return 1;
}
