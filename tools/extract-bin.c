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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define SCRIPT_CHECK_SIZE     0x40000
#define BINARY_MARKER_LINE    "###### BINARY-DATA-BEGIN"

int main(int argc, char *argv[])
{
	ssize_t rl1;
	struct stat stat_fs;
	size_t mlen, offs, bsize, fsize;

	char * pbuf, * needle;
	int ret, fd, error, rval;
	const char * filp, * markp;

	rval = 0;
	fd = -1;
	bsize = 0;
	error = 0;
	filp = NULL;
	pbuf = needle = NULL;
	markp = BINARY_MARKER_LINE;
	if (argc <= 1) {
		fputs("Error, no script specified.\n", stderr);
		fflush(stderr);
		rval = 1;
		goto err0;
	}

	if (argc >= 3) {
		char * endp = NULL;
		errno = 0;
		bsize = (size_t) strtoull(argv[2], &endp, 0);
		error = errno;
		if (error || endp == argv[2]) {
			fprintf(stderr, "Error, invalid binary size specified: %s\n",
				argv[2]);
			fflush(stderr);
			rval = 2;
			goto err0;
		}
	}

	filp = argv[1];
	fd = open(filp, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		error = errno;
		fprintf(stderr, "Error, cannot open file '%s': %s\n",
			filp, strerror(error));
		fflush(stderr);
		rval = 3;
		goto err0;
	}

	ret = fstat(fd, &stat_fs);
	if (ret == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to stat file '%s': %s\n",
			filp, strerror(error));
		fflush(stderr);
		rval = 4;
		goto err0;
	}

	if (!S_ISREG(stat_fs.st_mode) ||
		stat_fs.st_size <= 0 || stat_fs.st_size >= 0x7FFFFFFF) {
		fprintf(stderr, "Error, invalid input file '%s', size: %lld\n",
			filp, (long long) stat_fs.st_size);
		fflush(stderr);
		rval = 5;
		goto err0;
	}
	fsize = (size_t) stat_fs.st_size;

	pbuf = (char *) malloc(SCRIPT_CHECK_SIZE + 4);
	if (pbuf == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		rval = 6;
		goto err0;
	}

	rl1 = read(fd, pbuf, SCRIPT_CHECK_SIZE);
	if (rl1 <= 0) {
		error = errno;
		fprintf(stderr, "Error, failed to read '%s': %s\n",
			filp, strerror(error));
		fflush(stderr);
		rval = 7;
		goto err0;
	}

	pbuf[rl1 + 0] = pbuf[rl1 + 1] = '\0';
	pbuf[rl1 + 2] = pbuf[rl1 + 3] = '\0';

	mlen = strlen(markp);
	needle = (char *) memmem(pbuf, (size_t) rl1, markp, mlen);
	if (needle == NULL) {
		fprintf(stderr, "Error, binary marker not found: %s\n", markp);
		fflush(stderr);
		rval = 8;
		goto err0;
	}

	offs = (size_t) (needle - pbuf);
	offs += mlen;
	if (pbuf[offs] == '\r')
		offs++;
	if (pbuf[offs] != '\n') {
		fprintf(stderr, "Error, trailing EOL not found after marker: %s\n", markp);
		fflush(stderr);
		rval = 9;
		goto err0;
	}
	offs++; /* skip '\n' character */

	/* check binary size if specified */
	if (bsize > 0 && (bsize + offs) != fsize) {
		fprintf(stderr, "Error, incorrect binary size: %zu, expected: %zu\n",
			fsize - offs, bsize);
		fflush(stderr);
		rval = 10;
		goto err0;
	}

	if (lseek(fd, (off_t) offs, SEEK_SET) != (off_t) offs) {
		error = errno;
		fprintf(stderr, "Error, failed to set file pointer: %s\n", strerror(error));
		fflush(stderr);
		rval = 11;
		goto err0;
	}

	ret = fstat(STDOUT_FILENO, &stat_fs);
	if (ret == 0 && S_ISFIFO(stat_fs.st_mode)) {
		ret = fcntl(STDOUT_FILENO, F_GETPIPE_SZ, 0);
		if (ret < SCRIPT_CHECK_SIZE) {
			ret = fcntl(STDOUT_FILENO, F_SETPIPE_SZ, SCRIPT_CHECK_SIZE);
			if (ret < 0) {
				error = errno;
				fprintf(stderr, "Warning, failed to update pipe size: %s\n",
					strerror(error));
				fflush(stderr);
			}
		}

		/* enable blocked output */
		ret = fcntl(STDOUT_FILENO, F_GETFL, 0);
		if (ret > 0 && (ret & O_NONBLOCK) != 0) {
			ret &= ~O_NONBLOCK;
			ret = fcntl(STDOUT_FILENO, F_GETFL, ret);
		}
		if (ret < 0) {
			error = errno;
			fprintf(stderr, "Error, failed to enable blocked output: %s\n",
				strerror(error));
			fflush(stderr);
			rval = 12;
			goto err0;
		}
	}

	/* TODO: use `sendfile system call instead of `read/`write */
	for (;;) {
		rl1 = read(fd, pbuf, SCRIPT_CHECK_SIZE);
		if (rl1 <= 0)
			break;

		if (write(STDOUT_FILENO, pbuf, (size_t) rl1) != rl1) {
			rval = 13;
			error = errno;
			fprintf(stderr, "Error, failed to write output: %s\n",
				strerror(error));
			fflush(stderr);
			break;
		}
	}

err0:
	if (fd != -1)
		close(fd);
	if (pbuf != NULL)
		free(pbuf);
	return rval;
}
