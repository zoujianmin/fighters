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

int ftmsock_reopen(struct ftmsock * ftms,
	const char * new_netdev)
{
	int sockfd, err;

	sockfd = socket(ftms->ms_ipv6 ? AF_INET6 : AF_INET,
		SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sockfd == -1) {
		err = errno;
		fprintf(stderr, "Error, failed to create UDP socket: %s\n",
			strerror(err));
		fflush(stderr);
		goto err0;
	}

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
	struct ftmsock * fsock = NULL;

	if (mcaddr == NULL || mcnetdev == NULL || rport == 0
		wport == 0 || rport == wport) {
		fputs("Error, invalid function parameter given\n");
		fflush(stderr);
		return fsock;
	}

	fsock = (struct ftmsock *) calloc(0x1, sizeof(*fsock));
	if (fsock == NULL) {
		fputs("Error, System out of memory!\n", stderr);
		fflush(stderr);
		return NULL;
	}

	fsock->ms_magic = FIGHTER_MSOCK_MAGIC;
	strncpy(fsock->ms_addr, mcaddr, FIGHTER_ADDRSTRLEN - 1);
	strncpy(fsock->ms_netdev, mcnetdev, FIGHTER_NETDEV_SIZE - 1);
	fsock->ms_rfd = -1;
	fsock->ms_wfd = -1;
	fsock->ms_rport = rport;
	fsock->ms_wport = wport;
	fsock->ms_ipv6 = mc_ipv6 != 0;

	ret = ftmsock_reopen(fsock, NULL);
	if (ret < 0)
		goto err0;

	return fsock;
err0:
	free(fsock);
	return NULL;
}
