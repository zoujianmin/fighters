/*
 * Copyright (©) 2022 Ye Holmes <yeholmes@outlook.com>
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
#include <fcntl.h>
#include <unistd.h>

#include <time.h>
#include <poll.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ftmsock.h"

static int ftmsock_check(const struct ftmsock * ftms, int verbose)
{
	if (ftms == NULL ||
		ftms->ms_magic != FIGHTER_MSOCK_MAGIC) {
		if (verbose) {
			fprintf(stderr, "Error, invalid multicast handle: %p, magic: %#x\n",
				ftms, (ftms != NULL) ? ftms->ms_magic : 0x0);
			fflush(stderr);
		}
		return -1;
	}
	return ftms->ms_sockfd;
}

/*
 * Enable or disable multicast loop, and set TTL to `ttlval
 */
static void ftmsock_loop_ttl(int sockfd, int mloop, int ttlval, int delay)
{
	int ret, errn;

	ret = setsockopt(sockfd, IPPROTO_IP,
		IP_MULTICAST_LOOP, &mloop, sizeof(mloop));
	if (ret != -1)
		ret = setsockopt(sockfd, IPPROTO_IP,
			IP_MULTICAST_TTL, &ttlval, sizeof(ttlval));
	if (ret == -1) {
		errn = errno;
		fprintf(stderr, "Error, failed to set multicast socket option: %s\n",
			strerror(errn));
		fflush(stderr);
		return;
	}

	if (delay > 0) {
		struct timespec tspec;
		/* delay one second: */
		tspec.tv_sec = (time_t) delay;
		tspec.tv_nsec = 0;
		nanosleep(&tspec, NULL);
	}
}

int ftmsock_reopen(struct ftmsock * ftms,
	const char * new_netdev)
{
	int sockfd;
	int ret, errn;
	unsigned int if_idx;

	sockfd = ftmsock_check(ftms, 1);
	if (sockfd != -1) {
		close(sockfd);
		ftms->ms_sockfd = -1;
	}

	sockfd = -1;
	/* fetch the network device index */
	if (new_netdev == NULL)
		new_netdev = ftms->ms_netdev;
	else {
		strncpy(ftms->ms_netdev, new_netdev, FIGHTER_NETDEV_SIZE - 1);
		ftms->ms_netdev[FIGHTER_NETDEV_SIZE - 1] = '\0';
	}
	if_idx = if_nametoindex(new_netdev);
	if (if_idx == 0) {
		errn = errno;
		fprintf(stderr, "Error, invalid network device [%s]: %s\n",
			new_netdev, strerror(errn));
		fflush(stderr);
		return -1;
	}

	sockfd = socket(ftms->ms_ipv6 ? AF_INET6 : AF_INET,
		SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sockfd == -1) {
		errn = errno;
		fprintf(stderr, "Error, failed to create UDP socket: %s\n",
			strerror(errn));
		fflush(stderr);
		goto err0;
	}

	if (ftms->ms_ipv6) {
		// TODO: struct sockaddr_in6 v6addr;
		fputs("Error, multicast over IPv6 is not yet supported!\n", stderr);
		fflush(stderr);
		goto err0;
	} else {
		int optval;
		struct ip_mreqn mreq;
		struct sockaddr_in v4addr;
		struct sockaddr_in * addrp;

		optval = 1;
		ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (ret == -1) {
			errn = errno;
			fprintf(stderr, "Error, failed to REUSEADDR for UDP socket: %s\n",
				strerror(errn));
			fflush(stderr);
			goto err0;
		}
		/* bind multicast socket to specific local port */
		memset(&v4addr, 0, sizeof(v4addr));
		v4addr.sin_family = AF_INET;
		v4addr.sin_addr.s_addr = INADDR_ANY;
		v4addr.sin_port = htons(ftms->ms_rport);
		ret = bind(sockfd, (struct sockaddr *) &v4addr, sizeof(v4addr));
		if (ret == -1) {
			errn = errno;
			fprintf(stderr, "Error, failed to bind to local port %u: %s\n",
				(unsigned int) ftms->ms_rport, strerror(errn));
			fflush(stderr);
			goto err0;
		}

		/* setup the multicast group structure */
		memset(&mreq, 0, sizeof(mreq));
		ret = inet_pton(AF_INET, ftms->ms_addr, &(mreq.imr_multiaddr.s_addr));
		if (ret != 1) {
			fprintf(stderr, "Error, invalid IPv4 address: %s\n", ftms->ms_addr);
			fflush(stderr);
			goto err0;
		}
		mreq.imr_address.s_addr = INADDR_ANY;
		mreq.imr_ifindex = (int) if_idx;

		/* join the multicast group */
		ret = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
		if (ret == -1) {
			errn = errno;
			fprintf(stderr, "Error, failed to join multicast group: %s\n",
				strerror(errn));
			fflush(stderr);
			goto err0;
		}

		/* specify the interface of out-going packets */
		ret = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq));
		if (ret == -1) {
			errn = errno;
			fprintf(stderr, "Error, failed to specify multicast interface: %s\n",
				strerror(errn));
			fflush(stderr);
			goto err0;
		}

		/* setup the address for `sendto(...) */
		addrp = (struct sockaddr_in *) ftms->ms_send_addr;
		memset(addrp, 0, sizeof(*addrp));
		addrp->sin_family = AF_INET;
		addrp->sin_addr.s_addr = mreq.imr_multiaddr.s_addr;
		addrp->sin_port = htons(ftms->ms_wport);
	}

	ftmsock_loop_ttl(sockfd, 0, 5, 1);
	ftms->ms_ifidx = if_idx;
	ftms->ms_sockfd = sockfd;
	return 0;

err0:
	if (sockfd != -1)
		close(sockfd);
	return -1;
}

struct ftmsock * ftmsock_create(const char * mcaddr,
    const char * mcnetdev, unsigned short rport,
    unsigned short wport, int mc_ipv6)
{
	int ret;
	size_t fsize;
	struct ftmsock * fsock = NULL;

	if (mcaddr == NULL || mcnetdev == NULL || rport == 0 ||
		wport == 0 || rport == wport) {
		fputs("Error, invalid function parameter given\n", stderr);
		fflush(stderr);
		return fsock;
	}

	fsize = sizeof(*fsock);
	fsize += mc_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	fsock = (struct ftmsock *) calloc(0x1, fsize);
	if (fsock == NULL) {
		fputs("Error, System out of memory!\n", stderr);
		fflush(stderr);
		return NULL;
	}

	fsock->ms_magic = FIGHTER_MSOCK_MAGIC;
	strncpy(fsock->ms_addr, mcaddr, FIGHTER_ADDRSTRLEN - 1);
	strncpy(fsock->ms_netdev, mcnetdev, FIGHTER_NETDEV_SIZE - 1);
	fsock->ms_sockfd = -1;
	fsock->ms_rport = rport;
	fsock->ms_wport = wport;
	fsock->ms_ipv6 = (mc_ipv6 != 0) ? -1 : 0;
	fsock->ms_ifidx = 0;
	fsock->ms_send_addr = (void *) (((unsigned char *) fsock) + sizeof(*fsock));

	ret = ftmsock_reopen(fsock, NULL);
	if (ret < 0)
		goto err0;

	return fsock;
err0:
	fsock->ms_magic = 0;
	free(fsock);
	return NULL;
}

int ftmsock_send(struct ftmsock * ftms,
    const void * mptr, unsigned int length)
{
	ssize_t rl1;
	socklen_t slt;
	int sockfd, errn;

	sockfd = ftmsock_check(ftms, 1);
	if (sockfd < 0)
		return -1;

	if (mptr == NULL || length == 0) {
		fprintf(stderr, "Error, invalid parameters in [%s]: %p, %u\n",
			__FUNCTION__, mptr, length);
		fflush(stderr);
		return -2;
	}

	slt = ftms->ms_ipv6 ? sizeof(struct sockaddr_in6) :
		sizeof(struct sockaddr_in);
	rl1 = sendto(sockfd, mptr, (size_t) length, 0,
		(const struct sockaddr *) ftms->ms_send_addr, slt);
	if (rl1 != (ssize_t) length) {
		errn = errno;
		fprintf(stderr, "Error, failed to send multicast message: %s\n",
			strerror(errn));
		fflush(stderr);
		return -3;
	}

	return 0;
}

int ftmsock_recv(struct ftmsock * ftms,
    void * mptr, unsigned int length, int timeout)
{
	ssize_t rl1;
	socklen_t slt;
	int sockfd, errn;
	struct sockaddr * vaddrp;
	struct sockaddr_in v4addr;
	struct sockaddr_in6 v6addr;

	sockfd = ftmsock_check(ftms, 1);
	if (sockfd < 0)
		return -1;

	if (timeout != 0) {
		int ret;
		struct pollfd poll_fd;

		poll_fd.fd = sockfd;
		poll_fd.events = POLLIN | POLLPRI;
		poll_fd.revents = 0;
		ret = poll(&poll_fd, 0x1, timeout);
		if (ret == -1) {
			errn = errno;
			if (errn == EINTR) {
				/* interruped, no data available: */
				return 0;
			}
			fprintf(stderr, "Error, failed to poll socket %d with timeout %d: %s\n",
				sockfd, timeout, strerror(errn));
			fflush(stderr);
			return -1;
		}

		if (ret == 0)
			return 0; /* socket poll has timed out */
		if ((poll_fd.revents & POLLIN) == 0 || (poll_fd.revents & POLLPRI) != 0) {
			fprintf(stderr, "Error, socket poll has returned: %#x\n",
				(unsigned int) poll_fd.revents);
			fflush(stderr);
		}
	}

	slt = ftms->ms_ipv6 ? sizeof(v6addr) : sizeof(v4addr);
	vaddrp = ftms->ms_ipv6 ? ((struct sockaddr *) &v6addr) :
		((struct sockaddr *) &v4addr);
	rl1 = recvfrom(sockfd, mptr, length, 0, vaddrp, &slt);
	if (rl1 == -1) {
		errn = errno;
		if (errn == EINTR || errn == EAGAIN || errn == EWOULDBLOCK)
			return 0; /* interrupted or non-block read */
		fprintf(stderr, "Error, failed to read socket %d: %s\n",
			sockfd, strerror(errn));
		fflush(stderr);
		return -1;
	}
	return (int) rl1;
}

void ftmsock_destroy(struct ftmsock * ftms)
{
	int sockfd;

	if (ftms == NULL ||
		ftms->ms_magic != FIGHTER_MSOCK_MAGIC) {
		fputs("Error, invalid multicast handle specified!\n", stderr);
		fflush(stderr);
		return;
	}
	sockfd = ftms->ms_sockfd;
	if (sockfd != -1) {
		close(sockfd);
		ftms->ms_sockfd = -1;
	}

	ftms->ms_magic = 0;
	free(ftms);
}
