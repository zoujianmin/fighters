/*
 * Copyright (©) 2023 Ye Holmes <yeholmes@outlook.com>
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
#include <fcntl.h>
#include <time.h>

#include <poll.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "lua.h"
#include "lauxlib.h"

#define UDEV_NORMAL_FDS         8
#define UDEV_BUFSIZE            24576
#define UDEV_UEVENT_NUM         24

#define UDEV_UEVENT_HANDLER     0
#define UDEV_ROUTE_HANDLER      1
#define UDEV_NORMAL_HANDLER     2

struct poll_list {
	int                  uevent_fd;
	int                  route_fd;
	int                  normal_fd[UDEV_NORMAL_FDS];
};

#define UDEV_ADDR_SIZE          128
struct udev_msg {
	socklen_t            addrlen;
	unsigned int         msglen;
	unsigned char        addr[UDEV_ADDR_SIZE];
	unsigned char        msgbuf[UDEV_BUFSIZE];
};

static struct poll_list g_plist = {
	.uevent_fd = -1,
	.route_fd = -1,
	.normal_fd = { -1, -1, -1, -1, -1, -1, -1, -1 },
};

extern int luaopen_udev(lua_State * L);
typedef int (* process_evbuf)(lua_State * L, int fd, struct udev_msg * umsg);

static struct udev_msg * udev_msg_new(void)
{
	size_t msglen;
	struct udev_msg * msg;

	msglen = sizeof(struct udev_msg);
	msg = (struct udev_msg *) malloc(msglen);
	if (msg == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return NULL;
	}

	msg->addrlen = 0;
	msg->msglen = 0;
	return msg;
}

static int udev_readsock(int fd, struct udev_msg * msg, int * eofp)
{
	ssize_t rl1;

	*eofp = 0;
	msg->msglen = 0;
	msg->addrlen = sizeof(msg->addr);
	memset(msg->addr, 0, sizeof(msg->addr));
	rl1 = recvfrom(fd, msg->msgbuf, sizeof(msg->msgbuf) - 1,
		0, (struct sockaddr *) msg->addr, &msg->addrlen);

	if (rl1 == -1) {
		int error = errno;
		if (error == EAGAIN || error == EWOULDBLOCK)
			return 0;

		fprintf(stderr, "Error, failed to read socket %d: %s\n",
			fd, strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	msg->msglen = (unsigned int) rl1;
	msg->msgbuf[rl1] = '\0';
	if (rl1 == 0) {
		*eofp = 1;
		return 0;
	}
	return (int) rl1;
}

static int udev_readfd(int fd, struct udev_msg * msg, int * eofp)
{
	ssize_t rl1;

	*eofp = 0;
	msg->msglen = 0;
	msg->addrlen = 0;
	rl1 = read(fd, msg->msgbuf, sizeof(msg->msgbuf) - 1);
	if (rl1 == -1) {
		int error = errno;
		if (error == EAGAIN || error == EWOULDBLOCK)
			return 0;
		fprintf(stderr, "Error, failed to read file descriptor %d: %s\n",
			fd, strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	msg->msglen = (unsigned int) rl1;
	msg->msgbuf[rl1] = '\0';
	if (rl1 == 0) {
		*eofp = 1;
		return 0;
	}
	return (int) rl1;
}

static int socket_netlink(int proto, unsigned int groups)
{
	int ret, fd, optval;
	struct sockaddr_nl snl;

	fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, proto);
	if (fd == -1) {
		int error = errno;
		fprintf(stderr, "Error, failed to create NETLINK socket: %s\n", strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	snl.nl_family = AF_NETLINK;
	snl.nl_pad = 0;
	snl.nl_pid = 0;
	snl.nl_groups = groups;
	ret = bind(fd, (const struct sockaddr *) &snl, sizeof(snl));
	if (ret == -1) {
		int error = errno;
		close(fd);
		fprintf(stderr, "Error, failed to bind NETLINK socket: %s\n", strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	optval = 256 * 1024; /* 256K */
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
	if (ret == 0) {
		optval = 256 * 1024;
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval));
	}

	if (ret < 0) {
		int error = errno;
		close(fd);
		fprintf(stderr, "Error, failed to set socket buffer size: %s\n", strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}
	return fd;
}

static int open_uevent(lua_State * L)
{
	int ntop, sockfd, isopen;
	struct poll_list * plist;

	isopen = -1;
	sockfd = -1;
	if (lua_checkstack(L, 2) == 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TBOOLEAN)
		isopen = lua_toboolean(L, 1);

	plist = &g_plist;
	if (plist->uevent_fd != -1) {
		close(plist->uevent_fd);
		plist->uevent_fd = -1;
	}

	if (isopen == 0) {
		lua_pushboolean(L, 1);
		return 1;
	}

	/* re-open a netlink socket */
	sockfd = socket_netlink(NETLINK_KOBJECT_UEVENT, 0x1);
	if (sockfd < 0) {
		int error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "Error, failed to create netlink socket: %s", strerror(error));
		return 2;
	}

	plist->uevent_fd = sockfd;
	lua_pushinteger(L, sockfd);
	return 1;
}

static int open_route(lua_State * L)
{
	unsigned int grps;
	int ntop, sockfd, isopen;
	struct poll_list * plist;

	grps = 0;
	isopen = -1;
	sockfd = -1;
	if (lua_checkstack(L, 2) == 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop >= 1 && lua_type(L, 1) == LUA_TBOOLEAN)
		isopen = lua_toboolean(L, 1);
	if (ntop >= 1 && lua_type(L, 2) == LUA_TNUMBER)
		grps = (unsigned int) lua_tonumber(L, 2);

	plist = &g_plist;
	if (plist->route_fd != -1) {
		close(plist->route_fd);
		plist->route_fd = -1;
	}

	if (isopen == 0) {
		lua_pushboolean(L, 1);
		return 1;
	}

	/*
	 * socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3
	 * setsockopt(3, SOL_SOCKET, SO_SNDBUF, [32768], 4) = 0
	 * setsockopt(3, SOL_SOCKET, SO_RCVBUF, [1048576], 4) = 0
	 * setsockopt(3, SOL_NETLINK, NETLINK_EXT_ACK, [1], 4) = 0
	 * bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=0x1d8607f5}, 12) = 0
	 * getsockname(3, {sa_family=AF_NETLINK, nl_pid=493388, nl_groups=0x1d8607f5}, [12]) = 0
	 * setsockopt(3, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, [32], 4) = 0
	 * sendto(3, [{nlmsg_len=40, nlmsg_type=RTM_GETLINK, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1702976536, nlmsg_pid=0},
	 * {ifi_family=AF_UNSPEC, ifi_type=ARPHRD_NETROM, ifi_index=0, ifi_flags=0, ifi_change=0}, [{nla_len=8, nla_type=IFLA_EXT_MASK}, RTEXT_FILTER_VF]], 40, 0, NULL, 0) = 40
	 */

	if (grps == 0) {
		grps  = RTNLGRP_LINK;
		grps |= RTNLGRP_IPV4_IFADDR | RTNLGRP_IPV4_MROUTE | RTNLGRP_IPV4_ROUTE | RTNLGRP_IPV4_RULE;
		grps |= RTNLGRP_IPV4_NETCONF | RTNLGRP_IPV4_MROUTE_R;
		grps |= RTNLGRP_IPV6_IFADDR | RTNLGRP_IPV6_MROUTE | RTNLGRP_IPV6_ROUTE | RTNLGRP_IPV6_IFINFO;
		grps |= RTNLGRP_IPV6_NETCONF | RTNLGRP_IPV6_PREFIX | RTNLGRP_IPV6_RULE | RTNLGRP_IPV6_MROUTE_R;
	}

	/* re-open a netlink socket */
	sockfd = socket_netlink(NETLINK_ROUTE, grps);
	if (sockfd < 0) {
		int error = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "Error, failed to create netlink socket: %s", strerror(error));
		return 2;
	}

	plist->route_fd = sockfd;
	lua_pushinteger(L, sockfd);
	return 1;
}

static int handle_uevent(lua_State * L, int fd, struct udev_msg * umsg)
{
	int ntop, nevt, i;
	char * endp, * pbuf;
	char * ulist[UDEV_UEVENT_NUM];

	ntop = nevt = 0;
	pbuf = (char *) umsg->msgbuf;
	endp = pbuf + umsg->msglen;
	for (i = 0; i < UDEV_UEVENT_NUM; ++i)
		ulist[i] = NULL;

	while (*pbuf == '\0') { /* skip leading zero bytes */
		pbuf++;
		if (pbuf >= endp) {
			fprintf(stderr, "Error, invalid all zero uevent buffer: %u\n", umsg->msglen);
			fflush(stderr);
			lua_pushnil(L);
			return 1;
		}
	}

	nevt = 0;
	while (nevt < UDEV_UEVENT_NUM) {
		size_t plen;
		plen = strlen(pbuf);
		ulist[nevt++] = pbuf;
		pbuf += plen;

		if (pbuf >= endp)
			goto _next;
		while (*pbuf == '\0') {
			pbuf++; /* skip trailing zeros */
			if (pbuf >= endp)
				goto _next;
		}
	}

_next:
	ntop = lua_gettop(L);
	lua_createtable(L, 0, nevt + 2);
	if (lua_gettop(L) != (ntop + 1)) {
		lua_settop(L, ntop);
		fputs("Error, failed to create table for uevent.\n", stderr);
		fflush(stderr);
		lua_pushnil(L);
		return 1;
	}
	ntop++; /* number of elements on the stack */

	lua_pushinteger(L, fd);
	lua_setfield(L, ntop, "FILED");

	lua_pushstring(L, "uevent");
	lua_setfield(L, ntop, "SRCID");

	for (i = 0; i < UDEV_UEVENT_NUM; ++i) {
		char * equal;
		char * evtl = ulist[i];

		if (evtl == NULL)
			continue;
		equal = strchr(evtl, '=');
		if (equal == NULL)
			equal = strchr(evtl, '@');
		if (equal && equal != evtl) {
			*equal++ = '\0';
			if (*equal != '\0') {
				lua_pushstring(L, equal);
				lua_setfield(L, ntop, evtl);
			} else {
				fprintf(stderr, "Error, empty uevent line: '%s'\n", evtl);
				fflush(stderr);
			}
		} else {
			fprintf(stderr, "Error, equal not found in '%s'\n", evtl);
			fflush(stderr);
		}
	}

	lua_settop(L, ntop);
	return 1;
}

static int handle_route(lua_State * L, int fd, struct udev_msg * umsg)
{
	const struct sockaddr_nl * pnl;

	pnl = (const struct sockaddr_nl *) umsg->addr;
	if (umsg->addrlen != (socklen_t) sizeof(*pnl)) {
		fprintf(stderr, "Error, invalid size for iproute address: %u\n", umsg->addrlen);
		fflush(stderr);
		lua_pushnil(L);
		return 1;
	}

	if (pnl->nl_family != AF_NETLINK) {
		fprintf(stderr, "Error, invalid family for iproute message: %#x\n", pnl->nl_family);
		fflush(stderr);
		lua_pushnil(L);
		return 1;
	}

	lua_pushnil(L);
	return 1;
}

static int handle_normal(lua_State * L, int fd, struct udev_msg * umsg)
{
	int ntop;
	const char * pbuf;

	ntop = lua_gettop(L);
	lua_createtable(L, 0, 3);
	if (lua_gettop(L) != (ntop + 1)) {
		lua_settop(L, ntop);
		fputs("Error, failed to create lua table for normal.\n", stderr);
		fflush(stderr);
		lua_pushnil(L);
		return 1;
	}
	ntop++;

	pbuf = (const char *) umsg->msgbuf;
	lua_pushinteger(L, fd);
	lua_setfield(L, ntop, "FILED");

	lua_pushstring(L, "normal");
	lua_setfield(L, ntop, "SRCID");

	lua_pushlstring(L, pbuf, (size_t) umsg->msglen);
	lua_setfield(L, ntop, "RAWDATA");

	lua_settop(L, ntop);
	return 3;
}

static const process_evbuf g_handlers[] = {
	[UDEV_UEVENT_HANDLER]    = handle_uevent,
	[UDEV_ROUTE_HANDLER]     = handle_route,
	[UDEV_NORMAL_HANDLER]    = handle_normal,
};

static int read_anyfd(struct udev_msg * msg, int * phandle, int * pfd)
{
	ssize_t rl1;
	int idx, iseof;
	struct poll_list * plist;

	iseof = 0;
	plist = &g_plist;
	if (plist->uevent_fd >= 0) {
		rl1 = udev_readsock(plist->uevent_fd, msg, &iseof);
		if (rl1 > 0) {
			*pfd = plist->uevent_fd;
			*phandle = UDEV_UEVENT_HANDLER;
			return (int) rl1;
		}
	}

	if (plist->route_fd >= 0) {
		iseof = 0;
		rl1 = udev_readsock(plist->route_fd, msg, &iseof);
		if (rl1 > 0) {
			*pfd = plist->route_fd;
			*phandle = UDEV_ROUTE_HANDLER;
			return (int) rl1;
		}
	}

	for (idx = 0; idx < UDEV_NORMAL_FDS; ++idx) {
		if (plist->normal_fd[idx] >= 0) {
			iseof = 0;
			rl1 = udev_readfd(plist->normal_fd[idx], msg, &iseof);
			if (rl1 > 0) {
				*pfd = plist->normal_fd[idx];
				*phandle = UDEV_NORMAL_HANDLER;
				return (int) rl1;
			}
		}
	}
	return 0;
}

static int poll_events(lua_State * L)
{
	struct udev_msg * umsg;
	struct poll_list * plist;
	int timeo, ntop, ret, idx, numfds;
	struct pollfd pfds[UDEV_NORMAL_FDS + 2];

	idx = 0;
	numfds = 0;
	timeo = -1;
	umsg = udev_msg_new();
	if (umsg == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "System Out of Memory!");
		return 2;
	}

	ret = read_anyfd(umsg, &idx, &numfds);
	if (ret > 0) {
		process_evbuf handle = g_handlers[idx];
		ret = handle(L, numfds, umsg);
		free(umsg);
		return ret;
	}

	ntop = lua_gettop(L);
	if (ntop >= 0 && lua_type(L, 1) == LUA_TNUMBER)
		timeo = (int) lua_tonumber(L, 1);

	numfds = 0;
	plist = &g_plist;
	if (plist->uevent_fd != -1) {
		pfds[numfds].fd = plist->uevent_fd;
		pfds[numfds].events = POLLIN;
		pfds[numfds].revents = 0;
		numfds++;
	}

	if (plist->route_fd != -1) {
		pfds[numfds].fd = plist->route_fd;
		pfds[numfds].events = POLLIN;
		pfds[numfds].revents = 0;
		numfds++;
	}

	for (idx = 0; idx < UDEV_NORMAL_FDS; ++idx) {
		if (plist->normal_fd[idx] != -1) {
			pfds[numfds].fd = plist->normal_fd[idx];
			pfds[numfds].events = POLLIN;
			pfds[numfds].revents = 0;
			numfds++;
		}
	}

	if (numfds == 0) {
		/* no file descriptors to watch */
		if (timeo > 0) {
			struct timespec spec;
			spec.tv_sec = (time_t) (timeo / 1000);
			spec.tv_nsec = (long) ((timeo % 1000) * 1000000);
			nanosleep(&spec, NULL);
		} else if (timeo < 0) {
			fputs("Warning, udev pause due to no files to watch.\n", stderr);
			fflush(stderr);
			pause();
		}

		free(umsg);
		lua_pushboolean(L, 0);
		return 1;
	}

	ret = poll(pfds, (nfds_t) numfds, timeo);
	if (ret < 0) {
		int error = errno;
		fprintf(stderr, "Error, poll has failed in udev: %s\n", strerror(error));
		fflush(stderr);

		free(umsg);
		lua_pushnil(L);
		lua_pushfstring(L, "Error, poll has failed: %s", strerror(error));
		return 2;
	}

	if (ret == 0) {
		free(umsg);
		lua_pushboolean(L, 0);
		return 1;
	}

	for (idx = 0; idx < numfds; ++idx) {
		if (pfds[idx].revents != 0) {
			int iseof;
			ssize_t rl1;
			struct stat fst;
			process_evbuf handler;
			int fd = pfds[idx].fd;

			iseof = 0;
			if (fstat(fd, &fst) == 0 && S_ISSOCK(fst.st_mode))
				rl1 = udev_readsock(fd, umsg, &iseof);
			else
				rl1 = udev_readfd(fd, umsg, &iseof);
			if (rl1 > 0) {
				if (fd == plist->uevent_fd)
					handler = g_handlers[UDEV_UEVENT_HANDLER];
				else if (fd == plist->route_fd)
					handler = g_handlers[UDEV_ROUTE_HANDLER];
				else
					handler = g_handlers[UDEV_NORMAL_HANDLER];

				ret = handler(L, fd, umsg);
				free(umsg);
				return ret;
			}
		}
	}

	free(umsg);
	lua_pushboolean(L, 0);
	return 1;
}

static const luaL_Reg udev_funcs[] = {
	{ "uevent",            open_uevent },
	{ "iproute",           open_route },
	{ "poll",              poll_events },
	{ NULL,                NULL },
};

int luaopen_udev(lua_State * L)
{
	luaL_register(L, "udev", udev_funcs);
	return 1;
}
