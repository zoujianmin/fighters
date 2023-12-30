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
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

union float_val {
	float          fval;
	uint32_t       uval;
};

union double_val {
	double         dval;
	uint64_t       uval;
};

#define FLAG_DUMP_FLOAT    1
#define FLAG_DUMP_DOUBLE   2

int main(int argc, char *argv[])
{
	int flag = 0;
	int idx, error;

	if (argc > 1) {
		const char * arg;
		arg = argv[1];
		if (arg[0] == '-' && arg[1] == 'f' && arg[2] == '\0')
			flag = FLAG_DUMP_FLOAT;
		else if (arg[0] == '-' && arg[1] == 'd' && arg[2] == '\0')
			flag = FLAG_DUMP_DOUBLE;
	}

	if (argc <= 1 + (flag != 0)) {
		fprintf(stdout, "Usage:\n\t%s -1.0\n"
			"\t%s -f 0xbf800000\n"
			"\t%s -d 0xbff0000000000000\n",
			argv[0], argv[0], argv[0]);
		fflush(stdout);
		return 1;
	}

	error = 0;
	for (idx = 1 + (flag != 0); idx < argc; ++idx) {
		char * endptr;
		union float_val val0;
		union double_val val1;
		const char * arg = argv[idx];

		if (arg == NULL || arg[0] == '\0')
			continue;

		endptr = NULL;
		if (flag == FLAG_DUMP_FLOAT) {
			double vd;
			errno = 0;
			val0.uval = (uint32_t) strtoul(arg, &endptr, 0);
			error = errno;
			if (endptr == arg || error != 0) {
				fprintf(stderr, "Error, invalid 32-bit unsigned integer: %s\n", arg);
				fflush(stderr);
				continue;
			}
			vd = (double) val0.fval;
			fprintf(stdout, "Float32 value: %s => %.06f %a 0x%08x\n",
				arg, vd, vd, val0.uval);
			fflush(stdout);
		} else if (flag == FLAG_DUMP_DOUBLE) {
			errno = 0;
			val1.uval = (uint64_t) strtoull(arg, &endptr, 0);
			error = errno;
			if (endptr == arg || error != 0) {
				fprintf(stderr, "Error, invalid 64-bit unsigned integer: %s\n", arg);
				fflush(stderr);
				continue;
			}
			fprintf(stdout, "Float64 value: %s => %.06f %a 0x%08x%08x\n", arg,
				val1.dval, val1.dval, (unsigned int) (val1.uval >> 32), (unsigned int) val1.uval);
			fflush(stdout);
		} else {
			int ftype;
			double value;

			errno = 0;
			value = strtod(arg, &endptr);
			error = errno;
			if (endptr == arg || error != 0) {
				fprintf(stderr, "Error, invalid floating-point number: %s\n", arg);
				fflush(stderr);
				continue;
			}

			ftype = fpclassify(value);
			if (ftype == FP_NAN || ftype == FP_INFINITE) {
				fprintf(stderr, "Warning, '%s' is %s, ignored\n", arg,
					(ftype == FP_NAN) ? "nan" : "inf");
				fflush(stderr);
				continue;
			}

			val0.fval = (float) value;
			val1.dval = value;
			fprintf(stdout, "Floating-point number %s: %.06lf %a =>\n", arg, value, value);
			fprintf(stdout, "\tFloat32: 0x%08x\n\tFloat64: 0x%08x%08x\n", val0.uval,
				(unsigned int) (val1.uval >> 32), (unsigned int) val1.uval);
			fflush(stdout);
		}
	}

	return 0;
}
