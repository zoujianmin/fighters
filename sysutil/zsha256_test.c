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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "zsha256_util.h"

static unsigned char * load_file(const char * filp,
	size_t maxsize, size_t * filesize, int verbose)
{
	int error;
	int fd, ret;
	ssize_t rl1;
	size_t rsize;
	struct stat fst;
	unsigned char * rbuf;

	fd = -1;
	error = 0;
	ret = stat(filp, &fst);
	if (ret == -1) {
		if (verbose) {
			error = errno;
			fprintf(stderr, "Error, failed to stat(%p): %s\n",
				filp ? : "unknown", strerror(error));
			fflush(stderr);
			errno = error;
		}
		return NULL;
	}

	if (!S_ISREG(fst.st_mode)) {
		error = ENOENT;
		if (verbose) {
			fprintf(stderr, "Error, not a regular file: %s\n", filp);
			fflush(stderr);
		}
		errno = error;
		return NULL;
	}

	rsize = maxsize;
	if (maxsize > (size_t) fst.st_size)
		rsize = (size_t) fst.st_size;

	fd = open(filp, O_RDONLY);
	if (fd == -1) {
		error = errno;
		if (verbose) {
			fprintf(stderr, "Error, failed to open(%s): %s\n",
				filp, strerror(error));
			fflush(stderr);
		}
		errno = error;
		return NULL;
	}

	rbuf = (unsigned char *) malloc(rsize + 1);
	if (rbuf == NULL) {
		error = errno;
		if (verbose) {
			fprintf(stderr, "Error, system out of memory: %zu\n", rsize);
			fflush(stderr);
		}
		close(fd);
		errno = error;
		return NULL;
	}

	rl1 = read(fd, rbuf, rsize);
	if (rl1 == -1) {
		error = errno;
		if (verbose) {
			fprintf(stderr, "Error, failed to read(%p): %s\n",
				filp, strerror(error));
			fflush(stderr);
		}
		close(fd);
		free(rbuf);
		errno = error;
		return NULL;
	}

	close(fd);
	*filesize = (size_t) rl1;
	rbuf[rl1] = (unsigned char) 0;
	return rbuf;
}

int main(int argc, char *argv[])
{
	int idx, ret;
	struct zsha256 sha256;
	char output[ZSHA256_STRSIZE];

	for (idx = 1; idx < argc; ++idx) {
		size_t fsize;
		const char * filp;
		unsigned char * fdat;

		fsize = 0;
		filp = argv[idx];
		fdat = load_file(filp, 0x2000000, &fsize, 1);
		if (fdat == NULL)
			continue;

		zsha256_init(&sha256);
		ret = zsha256_update(&sha256, fdat, (unsigned int) fsize);
		if (ret == 0)
			ret = zsha256_final(&sha256, NULL, 0);
		if (ret < 0) {
			free(fdat);
			fprintf(stderr, "Error, failed to sh256sum(%s): %s\n",
				filp, strerror(-ret));
			fflush(stderr);
			continue;
		}

		free(fdat);
		zsha256_hex(output, sizeof(output), &sha256);
		fprintf(stdout, "%s  %s\n", output, filp);
	}
	return 0;
}
