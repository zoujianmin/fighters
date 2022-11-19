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

#include <uthash.h>
#include "cmhash.h"

/*
 * common hash structure definition
 */
struct cmhash {
	unsigned char *       cm_key;    /* pointer to private copy of hash-key buffer */
	unsigned int          cm_klen;   /* length of hash key in bytes */
	union cm_hval         cm_val;    /* simple hashed value */
	UT_hash_handle        cm_hh;     /* hash structure from uthash */
};

int cmhash_getval(cmhash_t chash_,
	const void * cmkey, unsigned int cmlen,
	union cm_hval * valp)
{
	struct cmhash * hashptr;
	struct cmhash * chash = (struct cmhash *) chash_;

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

int cmhash_addval(cmhash_t * chash_,
	const void * cmkey, unsigned int cmlen,
	const union cm_hval * valp, union cm_hval * oldval)
{
	struct cmhash * newhash;
	struct cmhash * hashptr, * oldhash;
	struct cmhash * * chash = (struct cmhash * *) chash_;

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

int cmhash_delval(cmhash_t * chash_,
	const void * cmkey, unsigned int cmlen,
	union cm_hval * oldval)
{
	struct cmhash * delhash;
	struct cmhash * hashptr, * oldhash;
	struct cmhash * * chash = (struct cmhash * *) chash_;

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
	if (oldval != NULL)
		*oldval = delhash->cm_val;
	delhash->cm_val.cm_uint64 = 0ull;
	free(delhash);

	if (hashptr != oldhash)
		*chash = hashptr;
	return 0;
}

int cmhash_iter(cmhash_t chash_, void * ppriv,
	int (* iter_func)(int, const cmhash_t, void *))
{
	int count = 0;
	struct cmhash * iterhash = NULL;
	struct cmhash * temphash = NULL;
	struct cmhash * chash = (struct cmhash *) chash_;

	if (chash == NULL || iter_func == NULL)
		return -EINVAL;
	HASH_ITER(cm_hh, chash, iterhash, temphash) {
		if (iter_func(count, iterhash, ppriv) < 0)
			break;
		count++;
	}
	return 0;
}

void cmhash_delete(cmhash_t * chash_)
{
	struct cmhash * hashptr, * oldhash;
	struct cmhash * iterhash, * temphash;
	struct cmhash * * chash = (struct cmhash * *) chash_;

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
