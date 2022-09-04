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
#include <stdlib.h>
#include <string.h>

#include "cmhash.h"

int cmhash_getval(struct cmhash * chash,
	const void * cmkey, unsigned int cmlen,
	union cm_hval * valp)
{
	struct cmhash * hashptr;

	hashptr = NULL;
	if (chash == NULL || cmkey == NULL || cmlen == 0) {
		fprintf(stderr, "Error, invalid arguments found in [%s]\n",
			__FUNCTION__);
		fflush(stderr);
		return -EINVAL;
	}

	HASH_FIND(cm_hh, chash, cmkey, cmlen, hashptr);
	if (hashptr == NULL)
		return -ENOENT;
	if (valp != NULL)
		*valp = hashptr->cm_val;
	return 0;
}

int cmhash_addval(struct cmhash * * chash,
	const void * cmkey, unsigned int cmlen,
	const union cm_hval * valp, union cm_hval * oldval)
{
	struct cmhash * newhash;
	struct cmhash * hashptr, * oldhash;

	newhash = NULL;
	if (chash == NULL || cmkey == NULL ||
		cmlen == 0 || valp == NULL) {
		fprintf(stderr, "Error, invalid arguments found in [%s]\n",
			__FUNCTION__);
		fflush(stderr);
		return -EINVAL;
	}

	hashptr = oldhash = *chash;
	HASH_FIND(cm_hh, hashptr, cmkey, cmlen, newhash);
	if (newhash == NULL) {
		size_t mlen;
		mlen = sizeof(*newhash) + 0x1 + cmlen;
		newhash = (struct cmhash *) calloc(0x1, mlen);
		if (newhash == NULL) {
			fprintf(stderr, "Error, system out of memory: %zu\n", mlen);
			fflush(stderr);
			if (hashptr != oldhash)
				*chash = hashptr;
			return -ENOMEM;
		}

		newhash->cm_key = (unsigned char *) newhash;
		newhash->cm_key += sizeof(*newhash);
		memcpy(newhash->cm_key, cmkey, cmlen);

		newhash->cm_klen = cmlen;
		newhash->cm_val = *valp;
		HASH_ADD_KEYPTR(cm_hh, hashptr, newhash->cm_key, cmlen, newhash);
	} else {
		/* TODO: verify that the keys are the same */
		if (oldval != NULL)
			*oldval = newhash->cm_val;
		newhash->cm_val = *valp;
	}

	if (hashptr != oldhash)
		*chash = hashptr;
	return 0;
}

int cmhash_delval(struct cmhash * * chash,
	const void * cmkey, unsigned int cmlen)
{
	struct cmhash * delhash;
	struct cmhash * hashptr, * oldhash;

	delhash = NULL;
	if (chash == NULL || cmkey == NULL || cmlen == 0) {
		fprintf(stderr, "Error, invalid arguments found in [%s]\n",
			__FUNCTION__);
		fflush(stderr);
		return -EINVAL;
	}

	hashptr = oldhash = *chash;
	if (hashptr == NULL)
		return 0;

	HASH_FIND(cm_hh, hashptr, cmkey, cmlen, delhash);
	if (delhash == NULL)
		return -ENOENT;

	HASH_DELETE(cm_hh, hashptr, delhash);
	delhash->cm_key = NULL;
	delhash->cm_klen = 0;
	delhash->cm_val.cm_uint64 = 0ull;
	free(delhash);

	if (hashptr != oldhash)
		*chash = hashptr;
	return 0;
}

int cmhash_iter(struct cmhash * chash, void * ppriv,
	int (* iter_func)(int, const struct cmhash *, void *))
{
	int count = 0;
	struct cmhash * iterhash = NULL;
	struct cmhash * temphash = NULL;

	if (chash == NULL || iter_func == NULL)
		return -EINVAL;
	HASH_ITER(cm_hh, chash, iterhash, temphash) {
		if (iter_func(count, iterhash, ppriv) < 0)
			break;
		count++;
	}
	return 0;
}

void cmhash_delete(struct cmhash * * chash)
{
	struct cmhash * hashptr, * oldhash;
	struct cmhash * iterhash, * temphash;

	iterhash = temphash = NULL;
	hashptr = (chash != NULL) ? *chash : NULL;
	if (hashptr == NULL)
		return;
	oldhash = hashptr;

	HASH_ITER(cm_hh, hashptr, iterhash, temphash) {
		HASH_DELETE(cm_hh, hashptr, iterhash);
		iterhash->cm_key = NULL;
		iterhash->cm_klen = 0;
		cm_hval_init(&iterhash->cm_val);
		free(iterhash);
	}
	if (hashptr != oldhash)
		*chash = hashptr;
}
