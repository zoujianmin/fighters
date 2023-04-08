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
#include <fcntl.h>
#include <unistd.h>

#include "cmhash.h"

#define MAX_KEYLEN 8

struct random_map {
	unsigned char * key;
	unsigned int keylen;
	unsigned int value;
	char keystr[MAX_KEYLEN * 2 + 8];
};

static int rand_fd;

static struct random_map * get_random_map(void)
{
	ssize_t rl1;
	unsigned char * rdat;
	struct random_map * rmap;
	unsigned int rvals[2], keylen, idx;

	rmap = NULL;
	rvals[0] = rvals[1] = 0;
	rl1 = read(rand_fd, rvals, 0x8);
	if (rl1 != 0x8) {
		fputs("Error, failed to read random device!\n", stderr);
		fflush(stderr);
		return rmap;
	}

	keylen = rvals[0];
	keylen %= MAX_KEYLEN;
	keylen++;

	rmap = (struct random_map *) malloc((size_t) (sizeof(*rmap) + keylen + 1));
	if (rmap == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return rmap;
	}

	rdat = (unsigned char *) rmap;
	rmap->key = rdat + sizeof(*rmap);
	rmap->keylen = keylen;
	rmap->value = rvals[1];
	rl1 = read(rand_fd, rmap->key, (size_t) keylen);
	if (rl1 != (ssize_t) keylen) {
		int error = errno;
		fprintf(stderr, "Error, failed to read binary key: %s\n",
			strerror(error));
		fflush(stderr);
		free(rmap);
		return NULL;
	}

	rmap->key[keylen] = (unsigned char) 0x0;
	for (idx = 0; idx < keylen; ++idx) {
		snprintf(&(rmap->keystr[idx * 2]), sizeof(rmap->keystr) - idx * 2,
			"%02x", (unsigned int) rmap->key[idx]);
	}
	return rmap;
}

static int iterate_lhash(int count, void * whatp, union cm_hval hval)
{
	struct random_map * rmap;

	(void) whatp;
	rmap = (struct random_map *) hval.cm_pointer;
	fprintf(stdout, "[%02d] INFO, hash found: %p, '%s' => %#x\n",
		count, rmap, rmap ? rmap->keystr : "", rmap ? rmap->value : 0);
	fflush(stdout);
	return 0;
}

#define HASH_NUM 32
int main(int argc, char *argv[])
{
	int ret, idx;
	int rfd, error;
	cmhash_t hash = NULL;
	struct random_map * rmaps[HASH_NUM];

	rand_fd = -1;
	rfd = open("/dev/urandom", O_RDONLY);
	if (rfd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to open urandom: %s\n",
			strerror(error));
		fflush(stderr);
		return 1;
	}
	rand_fd = rfd;

	for (idx = 0; idx < HASH_NUM; ++idx) {
		union cm_hval cmval;
		rmaps[idx] = get_random_map();
		if (rmaps[idx] != NULL) {
			cm_hval_init(&cmval);
			cmval.cm_pointer = rmaps[idx];
			ret = cmhash_addval(&hash,
				rmaps[idx]->key, rmaps[idx]->keylen, &cmval, NULL);
			if (ret < 0) {
				fprintf(stderr, "Error, failed to insert hash '%s': %d\n",
					rmaps[idx]->keystr, ret);
				fflush(stderr);
			}
		}
	}

	fprintf(stdout, "Number entries in the hash table: %u\n", cmhash_count(hash));
	if (rmaps[HASH_NUM / 2] != NULL) {
		union cm_hval cmval;
		cm_hval_init(&cmval);
		ret = cmhash_delval(&hash, rmaps[HASH_NUM / 2]->key,
			rmaps[HASH_NUM / 2]->keylen, &cmval);
		fprintf(stdout, "remove from hash returns %d, %p, %p\n",
			ret, rmaps[HASH_NUM / 2], cmval.cm_pointer);
	}
	fprintf(stdout, "Number entries in the hash table: %u\n", cmhash_count(hash));
	fflush(stdout);

	for (idx = 0; idx < HASH_NUM; ++idx) {
		union cm_hval cmval;
		struct random_map * rmap;
		rmap = rmaps[idx];
		if (rmap == NULL)
			continue;

		cm_hval_init(&cmval);
		ret = cmhash_getval(hash,
			rmap->key, rmap->keylen, &cmval);
		if (ret < 0) {
			fprintf(stderr, "[%02d] Error, failed to find hash '%s': %d\n",
				idx, rmap->keystr, ret);
			fflush(stderr);
		} else {
			fprintf(stdout, "[%02d] INFO, hash found: %p, %p, '%s' => %#x\n",
				idx, cmval.cm_pointer, rmap, rmap->keystr, rmap->value);
			fflush(stdout);
		}
		free(rmap);
		rmaps[idx] = NULL;
	}

	fprintf(stdout, "=========================================================\n");
	cmhash_iter(hash, NULL, iterate_lhash);

	cmhash_delete(&hash);
	close(rand_fd);
	rand_fd = -1;
	return 0;
}
