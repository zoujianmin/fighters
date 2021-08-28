/*
 * Copyright (©) 2019 - 2021 Ye Holmes <yeholmes@outlook.com>
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
#include <stdint.h>

typedef union {
	int64_t               sval;
	uint64_t              uval;
} large_int;

typedef unsigned long long large_uint;

static void bitdump32(const char * arg, uint32_t _val)
{
	int i, k;
	uint32_t val;
	char bit_buf[256];

	/*
	 *     28    24    20    16    12    8     4     0
	 *  1101  1100  0011  0010  0101  0000  1111  0000
	 * 31    27    23    19    15    11     7     3
	 */
	k = 0;
	bit_buf[k++] = '\t'; bit_buf[k++] = ' ';
	for (i = 7; i >= 0; --i) {
		val = (_val >> (i << 2)) & 0xF;
		bit_buf[k++] = '0' + ((val & (0x1 << 3)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 2)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 1)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 0)) != 0);
		bit_buf[k++] = ' '; bit_buf[k++] = ' ';
	}
	bit_buf[k++] = '\n'; bit_buf[k++] = '\0';

	fputs("\t-----------------------------------------------\n", stdout);
	fprintf(stdout, "\tValue [%s] (%#x, %u):\n", arg, _val, _val);
	fputs("\t    28    24    20    16    12    8     4     0\n", stdout);
	fputs(bit_buf, stdout);
	fputs("\t31    27    23    19    15    11     7     3\n", stdout);
}

static void bitdump64(const char * arg, large_uint _val)
{
	int i, k;
	large_uint val;
	char bit_buf[256];

	/*
	 *     60    56    52    48    44    40    36    32    28    24    20    16    12    8     4     0
	 *  1101  1100  0011  0010  0101  0000  1111  0000  1101  1100  0011  0010  0101  0000  1111  0000
	 * 63    59    55    51    47    43    39    35    31    27    23    19    15    11     7     3
	 */
	k = 0;
	bit_buf[k++] = '\t'; bit_buf[k++] = ' ';
	for (i = 15; i >= 0; --i) {
		val = (_val >> (i << 2)) & 0xF;
		bit_buf[k++] = '0' + ((val & (0x1 << 3)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 2)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 1)) != 0);
		bit_buf[k++] = '0' + ((val & (0x1 << 0)) != 0);
		bit_buf[k++] = ' '; bit_buf[k++] = ' ';
	}
	bit_buf[k++] = '\n'; bit_buf[k++] = '\0';

	fputs("\t-----------------------------------------------------------------------------------------------\n",
		stdout);
	fprintf(stdout, "\tValue [%s] (%#llx, %llu):\n", arg, _val, _val);
	fputs("\t    60    56    52    48    44    40    36    32    28    24    20    16    12    8     4     0\n",
		stdout);
	fputs(bit_buf, stdout);
	fputs("\t63    59    55    51    47    43    39    35    31    27    23    19    15    11     7     3\n",
		stdout);
}

int main(int argc, char *argv[])
{
	int idx;

	for (idx = 0x1; idx < argc; ++idx) {
		large_int lit;
		const char * arg;
		int base, neg_offs;

		base = 10;
		neg_offs = 0;
		arg = argv[idx];
		if (arg[0] == '-')
			neg_offs = 1;

		if (arg[neg_offs] == '0') {
			char cha = arg[neg_offs + 1];
			if (cha == 'x' || cha == 'X')
				base = 16;
			else if (cha == 'b' || cha == 'B')
				base = 2;
			else /* if (cha == 'o' || cha == 'O') */
				base = 8;
		}

		lit.uval = (uint64_t) strtoull(arg + neg_offs, NULL, base);
		if (neg_offs != 0) {
			int32_t sval;
			lit.sval = 0 - lit.sval;
			sval = (int32_t) lit.sval;
			if (lit.sval == (int64_t) sval)
				bitdump32(arg, (uint32_t) lit.uval);
			else
				bitdump64(arg, lit.uval);
		} else {
			if ((lit.uval & 0xFFFFFFFF) == lit.uval)
				bitdump32(arg, (uint32_t) lit.uval);
			else
				bitdump64(arg, lit.uval);
		}
	}

	return 0;
}
