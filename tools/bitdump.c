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

static __attribute__((noinline)) void bit_dump_32(const char * arg, unsigned int _val)
{
	int i, k;
	unsigned int val;
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

static __attribute__((noinline)) void bit_dump_64(const char * arg, unsigned long long _val)
{
	int i, k;
	unsigned int val;
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
	int i, ba;
	unsigned long long val;
	const char *arg;

	for (i = 0x1; i < argc; ++i) {
		arg = argv[i];

		ba = 10;
		if (arg[0] == '0') {
			if ((arg[1] == 'x') || (arg[1] == 'X'))
				ba = 16;
			else
				ba = 8;
		}

		val = strtoull(arg, NULL, ba);
		if ((val & 0xFFFFFFFF) == val)
			bit_dump_32(arg, (unsigned int) val);
		else
			bit_dump_64(arg, val);
	}

	return 0;
}
