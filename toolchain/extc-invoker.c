/*
 * Copyright (©) 2021 Ye Holmes <yeholmes@outlook.com>
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
#include <unistd.h>

#ifndef EXTC_LTO_FIXUP
#define EXTC_LTO_FIXUP 0
#endif
#ifndef EXTC_BINDIR
#define EXTC_BINDIR "bin"
#endif

#ifndef EXTC_ROOT
#error EXTC_ROOT not defined
#endif
#ifndef EXTC_PREFIX
#error EXTC_PREFIX not defined
#endif

int main(int argc, char *argv[])
{
	int ret, idx;
	size_t prelen;
	char * real, * * args;
	const char * arg0, * name;
	const char * prefix, * root;

	real = NULL;
	args = NULL;
	if (argc < 1 || argv[0] == NULL) {
		fprintf(stderr, "Error, invalid argc/argv[0]: %d/%p\n",
			argc, argv[0]);
		fflush(stderr);
		return 1;
	}

	prefix = EXTC_PREFIX;
	prelen = strlen(prefix);
	arg0 = strrchr(argv[0], '/');
	if (arg0 != NULL)
		arg0++;
	else
		arg0 = argv[0];
	ret = strncmp(arg0, prefix, prelen);
	if (ret != 0) {
		fprintf(stderr, "Error, invalid toolchain prefix: %s\n", arg0);
		fflush(stderr);
		return 2;
	}

	name = arg0;
	root = EXTC_ROOT "/" EXTC_BINDIR;
#if EXTC_LTO_FIXUP
	arg0 += prelen;
	if (strcmp(arg0, "ar") == 0 ||
		strcmp(arg0, "nm") == 0 ||
		strcmp(arg0, "ranlib") == 0) {
		ret = asprintf(&real, "%s/%sgcc-%s", root, prefix, arg0);
	} else {
		ret = asprintf(&real, "%s/%s", root, name);
	}
#else
	ret = asprintf(&real, "%s/%s", root, name);
#endif
	if (ret <= 0) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return 3;
	}

	if (access(real, X_OK) != 0) {
		fprintf(stderr, "Error, toolchain not found: %s\n", real);
		fflush(stderr);
		free(real);
		return 4;
	}

	args = (char * *) malloc((size_t) ((argc + 1) * sizeof(char *)));
	if (args == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		free(real);
		return 5;
	}

	args[0] = real;
	for (idx = 1; idx < argc; ++idx)
		args[idx] = argv[idx];
	args[argc] = NULL;
	execv(real, args);
	fprintf(stderr, "Error, failed to invoke %s: %s\n",
		real, strerror(errno));
	fflush(stderr);
	free(real);
	free((void *) args);
	return 6;
}
