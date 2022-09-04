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

/*
 * ABOUT: Common Hash utility for C, based upon UTHASH
 */

#ifndef COMMON_HASH_H
#define COMMON_HASH_H 1

#include <uthash.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* hash values types */
union cm_hval {
	int32_t               cm_int;
	uint32_t              cm_uint;
	int64_t               cm_int64;
	uint64_t              cm_uint64;
	long                  cm_long;
	unsigned long         cm_ulong;
	void *                cm_pointer;
};

static inline void cm_hval_init(union cm_hval * cmp)
{
	/* set maximum size of all 8 bytes to zero */
	cmp->cm_uint64 = 0ull;
}

/*
 * common hash structure definition
 */
struct cmhash {
	unsigned char *       cm_key;    /* pointer to private copy of hash-key buffer */
	unsigned int          cm_klen;   /* length of hash key in bytes */
	union cm_hval         cm_val;    /* simple hashed value */
	UT_hash_handle        cm_hh;     /* hash structure from uthash */
};

int cmhash_getval(struct cmhash * chash,
	const void * cmkey, unsigned int cmlen,
	union cm_hval * valp);

int cmhash_addval(struct cmhash * * chash,
	const void * cmkey, unsigned int cmlen,
	const union cm_hval * valp, union cm_hval * oldval);

int cmhash_delval(struct cmhash * * chash,
	const void * cmkey, unsigned int cmlen);

void cmhash_delete(struct cmhash * * chash);

/*
 * Iterate over the hash set WITHOUT MODIFYING,
 * JUST DO NOT MODIFY THE HASH TABLE.
 * Note that if `iter_func returns negative value,
 * the iteration will stop.
 */
int cmhash_iter(struct cmhash * chash, void * ppriv,
	int (* iter_func)(int, const struct cmhash *, void *));

#ifdef __cplusplus
};
#endif
#endif
