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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ftmsock.h"
#include "mc-test.h"

int main(int argc, char *argv[])
{
	int ret;
	const char * netdev;
	struct ftmsock * ftm;
	unsigned char * mbuf;

	netdev = (argc > 1) ? argv[1] : "enp8s0";
	ftm = ftmsock_create(FTMC_TEST_ADDR, netdev,
		FTMC_TEST_WPORT, FTMC_TEST_RPORT, 0);
	if (ftm == NULL)
		return 1;

	mbuf = (unsigned char *) malloc(FTMC_TEST_BUFSIZ);
	if (mbuf == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		ftmsock_destroy(ftm);
		return 2;
	}


	for (;;) {
		unsigned int msglen;
		ret = ftmsock_recv(ftm, mbuf, FTMC_TEST_BUFSIZ - 1, 1000);
		if (ret == 0)
			continue;
		if (ret < 0) {
			fprintf(stderr, "Error, Message recv has returned: %d\n", ret);
			fflush(stderr);
			break;
		}

		msglen = (unsigned int) ret;
		mbuf[msglen] = '\0';
		fprintf(stdout, "Received message: [%s]\n", (const char *) mbuf);
		fflush(stdout);

		ret = ftmsock_send(ftm, mbuf, msglen);
		fprintf(stdout, "Message send has returned: %d\n", ret);
		fflush(stdout);
	}

	free(mbuf);
	ftmsock_destroy(ftm);
	return 0;
}
