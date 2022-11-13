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

/*
 * Adapted from: https://blog.csdn.net/maxzero/article/details/81773443
 *
 * Simple SHA256 Implementation in C
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>

#include "zsha256_util.h"

#define SHA256_BLOCK_SIZE    64
#define SHA256_COVER_SIZE   128

#define SHFR(x, n) (((x) >> (n)))
#define ROTR(x, n) (((x) >> (n)) | ((x) << ((sizeof(x) << 3) - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> ((sizeof(x) << 3) - (n))))

#define CHX(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ( (x) & (z)) ^ ((y) & (z)))

#define BSIG0(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

static const uint32_t keyvals[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const char * zsha256_hex(
	char * pbuf, uint32_t buflen,
	const struct zsha256 * hash)
{
	size_t plen, clen;
	uint32_t idx, blen;
	const uint8_t * pdat;

	clen = 0;
	plen = (size_t) buflen;
	blen = sizeof(uint32_t) * 0x8;
	pdat = (const uint8_t *) hash->hashval;
	for (idx = 0; idx < blen; idx += 0x4) {
		snprintf(pbuf + clen, plen - clen, "%02x%02x%02x%02x",
			(uint32_t) pdat[0], (uint32_t) pdat[1],
			(uint32_t) pdat[2], (uint32_t) pdat[3]);
		pdat += 0x4;
		clen += 0x8;
	}
	return pbuf;
}

static void ztransform(const uint8_t * msg, uint32_t * hashval)
{
	int i, j = 0;
	uint32_t t1, t2;
	uint32_t wval[64];
	uint32_t a0, b1, c2, d3, e4, f5, g6, h7;

	for (i = 0; i < 16; i++) {
		uint32_t msg0 = (uint32_t) msg[j];
		uint32_t msg1 = (uint32_t) msg[j + 1];
		uint32_t msg2 = (uint32_t) msg[j + 2];
		uint32_t msg3 = (uint32_t) msg[j + 3];
		wval[i] = (msg0 << 24) | (msg1 << 16) | (msg2 << 8) | msg3;
		j += 4;
    }

	for (i = 16; i < 64; i++) {
		uint32_t w0 = wval[i - 2];
		uint32_t w1 = wval[i - 7];
		uint32_t w2 = wval[i - 15];
		uint32_t w3 = wval[i - 16];
		wval[i] = SSIG1(w0) + w1 + SSIG0(w2) + w3;
	}

	a0 = hashval[0]; b1 = hashval[1];
	c2 = hashval[2]; d3 = hashval[3];
	e4 = hashval[4]; f5 = hashval[5];
	g6 = hashval[6]; h7 = hashval[7];

	for (i = 0; i < 64; i++) {
		t1 = h7 + BSIG1(e4) + CHX(e4, f5, g6) + keyvals[i] + wval[i];
		t2 = BSIG0(a0) + MAJ(a0, b1, c2);

		h7 = g6; g6 = f5;
		f5 = e4; e4 = d3 + t1;
		d3 = c2; c2 = b1;
		b1 = a0; a0 = t1 + t2;
	}

	hashval[0] += a0; hashval[1] += b1;
	hashval[2] += c2; hashval[3] += d3;
	hashval[4] += e4; hashval[5] += f5;
	hashval[6] += g6; hashval[7] += h7;
}

static inline uint32_t zsha256_bswap32(uint32_t uintval)
{
	uint32_t retval;
	retval = htobe32(uintval);
	return retval;
}

void zsha256_init(struct zsha256 * hash)
{
	if (hash == NULL)
		return;
	hash->hashlen = 0;
	hash->hashval[0] = zsha256_bswap32(0x6a09e667);
	hash->hashval[1] = zsha256_bswap32(0xbb67ae85);
	hash->hashval[2] = zsha256_bswap32(0x3c6ef372);
	hash->hashval[3] = zsha256_bswap32(0xa54ff53a);
	hash->hashval[4] = zsha256_bswap32(0x510e527f);
	hash->hashval[5] = zsha256_bswap32(0x9b05688c);
	hash->hashval[6] = zsha256_bswap32(0x1f83d9ab);
	hash->hashval[7] = zsha256_bswap32(0x5be0cd19);
}

int zsha256_update(struct zsha256 * hash,
	const uint8_t * srcp, uint32_t srclen)
{
	uint32_t shaval[8];
	uint32_t idx, nblks, left;

	if (hash == NULL)
		return -EINVAL;
	if (hash->hashlen == ZSHA256_DONE)
		return -EACCES;
	for (idx = 0; idx < 8; ++idx)
		shaval[idx] = zsha256_bswap32(hash->hashval[idx]);

	nblks = srclen / SHA256_BLOCK_SIZE;
	left = srclen % SHA256_BLOCK_SIZE;
	for (idx = 0; idx < nblks; ++idx) {
		ztransform(srcp, shaval);
		srcp += SHA256_BLOCK_SIZE;
	}

	hash->hashlen += nblks * SHA256_BLOCK_SIZE;
	for (idx = 0; idx < 8; ++idx)
		hash->hashval[idx] = zsha256_bswap32(shaval[idx]);
	if (left > 0)
		return zsha256_final(hash, srcp, left);
	return 0;
}

int zsha256_final(struct zsha256 * hash,
	const uint8_t * srcp, uint32_t srclen)
{
	uint32_t shaval[8];
	uint32_t idx, nblks;
	uint32_t cover_size, totlen;
	uint8_t cover_data[SHA256_COVER_SIZE];

	if (hash == NULL)
		return -EINVAL;
	if (hash->hashlen == ZSHA256_DONE) {
		if (srcp && srclen > 0)
			return -EACCES;
		return 0;
	}
	if (srclen > SHA256_BLOCK_SIZE)
		return -ERANGE;

	cover_size = (srclen < 56) ? SHA256_BLOCK_SIZE : SHA256_COVER_SIZE;
	memset(cover_data, 0, SHA256_COVER_SIZE);
	if (srclen > 0) {
		memcpy(cover_data, srcp, srclen);
	}

	totlen = srclen + hash->hashlen;
	totlen = totlen * 0x8;
	cover_data[srclen] = 0x80;
	cover_data[cover_size - 4] = (uint8_t) (totlen >> 24);
	cover_data[cover_size - 3] = (uint8_t) (totlen >> 16);
	cover_data[cover_size - 2] = (uint8_t) (totlen >> 8);
	cover_data[cover_size - 1] = (uint8_t) totlen;

	for (idx = 0; idx < 8; ++idx)
		shaval[idx] = zsha256_bswap32(hash->hashval[idx]);

	srcp = cover_data;
	nblks = cover_size / SHA256_BLOCK_SIZE;
	for (idx = 0; idx < nblks; ++idx) {
		ztransform(srcp, shaval);
		srcp += SHA256_BLOCK_SIZE;
	}

	hash->hashlen = ZSHA256_DONE;
	for (idx = 0; idx < 8; ++idx)
		hash->hashval[idx] = zsha256_bswap32(shaval[idx]);
	return 0;
}
