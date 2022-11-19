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
#include "apputil.h"

int main(int argc, char *argv[])
{
	int idx, ret;
	struct zsha256 sha256;
	char output[ZSHA256_STRSIZE];

	for (idx = 1; idx < argc; ++idx) {
		const char * filp;
		unsigned int fsize;
		unsigned char * fdat;

		fsize = 0;
		filp = argv[idx];
		fdat = appf_readfile(filp, 0x2000000, &fsize, 1);
		if (fdat == NULL)
			continue;

		zsha256_init(&sha256);
		ret = zsha256_update(&sha256, fdat, fsize);
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
