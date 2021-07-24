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

/* external GNU toolchain wrapper */
struct wrapper {
	int               orig_argc;
	char * *          orig_argv;
	char *            real_path;
	const char *      staging;
	const char *      output;

	int               max_argc;
	int               new_argc;
	char * *          new_argv;

	unsigned int      d_kernel : 1;
	unsigned int      d_uboot : 1;
	unsigned int      found_l : 1;
	unsigned int      found_L : 1;
	unsigned int      f_cSE : 1;
	unsigned int      f_nostdinc : 1;
	unsigned int      f_nostdincpp : 1;
	unsigned int      f_nostdlib : 1;
};

#ifndef EXTC_BINDIR
#define EXTC_BINDIR "bin"
#endif
#ifndef EXTC_ROOT
#error EXTC_ROOT not defined
#endif

#define EXTC_WRAPPER "Wrapper: "
#define EXTC_NOINL __attribute__((noinline))

static int wrapper_init(struct wrapper * pw,
	int argc, char * argv[]) EXTC_NOINL;

static void wrapper_iterate(struct wrapper * pw) EXTC_NOINL;

static void wrapper_combine(struct wrapper * pw) EXTC_NOINL;

static void wrapper_debug(const struct wrapper * pw) EXTC_NOINL;

static void wrapper_destroy(struct wrapper * pw) EXTC_NOINL;

static void wrapper_nomem(int lino) __attribute__((noreturn));

static void wrapper_dump_argv(int argc, char * * argv) EXTC_NOINL;

int main(int argc, char *argv[])
{
	struct wrapper wrap;

	if (argc < 1 || argv[0] == NULL) {
		fprintf(stderr, "Error, invalid argc/argv[0]: %d/%p\n",
			argc, argv[0]);
		fflush(stderr);
		return 1;
	}

	memset(&wrap, 0, sizeof(wrap));
	if (wrapper_init(&wrap, argc, argv) < 0) {
		wrapper_destroy(&wrap);
		return 2;
	}

	wrapper_iterate(&wrap);
	wrapper_combine(&wrap);
	wrapper_debug(&wrap);
	execv(wrap.real_path, wrap.new_argv);
	fprintf(stderr, EXTC_WRAPPER "Error, failed to invoke %s: %s\n",
		wrap.real_path, strerror(errno));
	fflush(stderr);
	return 3;
}

void wrapper_nomem(int lino)
{
	fprintf(stderr, EXTC_WRAPPER "Error, system out of memory at line: %d\n", lino);
	fflush(stderr);
	exit(4);
}

int wrapper_init(struct wrapper * pw, int argc, char * argv[])
{
	int ret;
	char * real;
	const char * bn, * prefix;

	pw->orig_argc = argc;
	pw->orig_argv = (char * *) argv;
	bn = strrchr(argv[0], '/');
	if (bn != NULL)
		bn++;
	else
		bn = argv[0];

	real = NULL;
	prefix = EXTC_ROOT "/" EXTC_BINDIR;
	ret = asprintf(&real, "%s/%s", prefix, bn);
	if (ret <= 0)
		wrapper_nomem(__LINE__);
	pw->real_path = real;

	if (access(real, X_OK) != 0) {
		fprintf(stderr, EXTC_WRAPPER "Error, toolchain not found: %s\n", bn);
		fflush(stderr);
		return -1;
	}

	pw->staging = getenv("FSTAGING_DIR");
	if (pw->staging == NULL) {
		fputs(EXTC_WRAPPER "Warning, `FSTAGING_DIR not defined!\n", stderr);
		fflush(stderr);
	}
	return 0;
}

void wrapper_iterate(struct wrapper * pw)
{
	int idx, argc;
	char * * argv;

	argc = pw->orig_argc;
	argv = pw->orig_argv;
	for (idx = 1; idx < argc; ++idx) {
		const char * argp;

		argp = argv[idx];
		if (argp == NULL)
			break;
		if (argp[0] != '-')
			continue;

		switch (argp[1]) {
		case 'c':
		case 'E':
		case 'S':
			if (argp[2] == '\0')
				pw->f_cSE = 1;
			break;

		case 'D':
			if (argp[2] == '_' && argp[3] == '_') {
				if (strcmp(argp, "-D__KERNEL__") == 0)
					pw->d_kernel = 1;
				else if (strcmp(argp, "-D__UBOOT__") == 0)
					pw->d_uboot = 1;
			}
			break;

		case 'l':
			pw->found_l = 1;
			break;

		case 'L':
			pw->found_L = 1;
			break;

		case 'n':
			if (strcmp(argp, "-nostdinc") == 0)
				pw->f_nostdinc = 1;
			else if (strcmp(argp, "-nostdinc++") == 0)
				pw->f_nostdincpp = 1;
			else if (strcmp(argp, "-nostdlib") == 0)
				pw->f_nostdlib = 1;
			break;

		case 'o':
			if (argp[2] == '\0' && (idx + 1) < argc) {
				idx++;
				pw->output = argv[idx];
			}
			break;

		case 'W':
			if (argp[2] == 'l' && argp[3] == ',') {
				if (strcmp(argp, "-Wl,-nostdlib") == 0)
					pw->f_nostdlib = 1;
			}
			break;

		default:
			break;
		}
	}
}

static void wrapper_combine_(struct wrapper * pw)
{
	char * * argv;
	int idx, argc, args;

	args = pw->max_argc;
	argc = pw->new_argc;
	argv = pw->new_argv;
	if ((args - argc) <= pw->orig_argc) {
		args = argc + pw->orig_argc + 1;
		argv = (char * *) realloc((void *) argv,
			(size_t) (args * sizeof(char *)));
		if (argv == NULL)
			wrapper_nomem(__LINE__);
		pw->max_argc = args;
		pw->new_argv = argv;
	}

	pw->new_argv[0] = pw->real_path;
	for (idx = 1; idx < pw->orig_argc; ++idx) {
		pw->new_argv[argc + idx] = pw->orig_argv[idx];
	}
	argc += pw->orig_argc;
	pw->new_argv[argc] = NULL;
}

static void wrapper_addarg(struct wrapper * pw, char * newarg, int alloc)
{
	int argc, args;
	char * * argv;

	args = pw->max_argc;
	argc = pw->new_argc;
	argv = pw->new_argv;
	if ((argc + 1) >= args) {
		args = (args < 3) ? 3 : (args << 1);
		argv = (char * *) realloc((void *) argv,
			(size_t) (args * sizeof(char *)));
		if (argv == NULL)
			wrapper_nomem(__LINE__);
		pw->max_argc = args;
		pw->new_argv = argv;
	}

	argc++;
	if (alloc != 0) {
		argv[argc] = strdup(newarg);
		if (argv[argc] == NULL)
			wrapper_nomem(__LINE__);
	} else
		argv[argc] = newarg;
	pw->new_argc = argc;
}

#ifdef EXTC_CFLAGS
static void wrapper_addargs(struct wrapper * pw, const char * cflags)
{
	char * flags, * start;

	if (cflags[0] == '\0')
		return;
	flags = strdup(cflags);
	if (flags == NULL)
		wrapper_nomem(__LINE__);

	start = flags;
	while (*start != '\0') {
		char cha, * end;

		cha = *start;
		while (cha == ' ' || cha == '\t') {
			start++;
			cha = *start;
		}

		end = start;
		while (cha != ' ' && cha != '\t') {
			if (cha == '\0')
				break;
			end++;
			cha = *end;
		}

		if (cha == '\0') {
			if (start != end)
				wrapper_addarg(pw, start, 1);
			break;
		}

		*end++ = '\0';
		wrapper_addarg(pw, start, 1);
		start = end;
	}
	free(flags);
}
#endif

void wrapper_combine(struct wrapper * pw)
{
	int ret;
	char argbuf[64], * newarg;

	if (pw->d_kernel != 0 || pw->d_uboot != 0) {
		wrapper_combine_(pw);
		return;
	}

#ifdef EXTC_CFLAGS
	wrapper_addargs(pw, EXTC_CFLAGS);
#endif

	if (pw->f_nostdinc != 0 || pw->f_nostdincpp != 0)
		goto linkopts;

	if (pw->staging != NULL) {
		strcpy(argbuf, "-idirafter");
		wrapper_addarg(pw, argbuf, 1);
		newarg = NULL;
		ret = asprintf(&newarg, "%s/usr/include", pw->staging);
		if (ret <= 0)
			wrapper_nomem(__LINE__);
		wrapper_addarg(pw, newarg, 0);
	}

linkopts:
	if (pw->f_cSE != 0 || pw->f_nostdlib != 0) {
		wrapper_combine_(pw);
		return;
	}

	if (pw->staging != NULL &&
		(pw->found_l != 0 || pw->found_L != 0)) {
		newarg = NULL;
		ret = asprintf(&newarg, "-L%s/usr/lib", pw->staging);
		if (ret <= 0)
			wrapper_nomem(__LINE__);
		wrapper_addarg(pw, newarg, 0);

		newarg = NULL;
		ret = asprintf(&newarg, "-Wl,-rpath-link=%s/usr/lib", pw->staging);
		if (ret <= 0)
			wrapper_nomem(__LINE__);
		wrapper_addarg(pw, newarg, 0);
	}
	wrapper_combine_(pw);
}

void wrapper_debug(const struct wrapper * pw)
{
	const char * Debug;
	char * bakup, * debug, * slash;

	Debug = getenv("EXTC_DEBUG");
	if (Debug == NULL || Debug[0] == '\0')
		return;

	bakup = debug = strdup(Debug);
	if (debug == NULL)
		wrapper_nomem(__LINE__);

	slash = strchr(debug, '/');
	if (slash == debug) {
		fprintf(stderr, "Error, invalid EXTC_DEBUG: %s\n", Debug);
		fflush(stderr);
		goto ndebug;
	}

	if (slash != NULL) {
		const char * bn;

		*slash++ = '\0';
		if (pw->output == NULL)
			goto ndebug;

		bn = strrchr(pw->output, '/');
		if (bn != NULL)
			bn++;
		else
			bn = pw->output;

		if (strcmp(debug, bn) != 0)
			goto ndebug;
		debug = slash;
	}

	if (debug[0] == '1' && debug[1] == '\0')
		wrapper_dump_argv(pw->orig_argc + pw->new_argc, pw->new_argv);
ndebug:
	free(bakup);
}

void wrapper_destroy(struct wrapper * pw)
{
	int idx;

	if (pw->real_path != NULL) {
		free(pw->real_path);
		pw->real_path = NULL;
	}

	if (pw->new_argc > 0) {
		for (idx = 1; idx <= pw->new_argc; ++idx) {
			free(pw->new_argv[idx]);
			pw->new_argv[idx] = NULL;
		}
		pw->max_argc = 0;
		pw->new_argc = 0;
		pw->new_argv[0] = NULL;
		free((void *) pw->new_argv);
		pw->new_argv = NULL;
	}
}

void wrapper_dump_argv(int argc, char * * argv)
{
	int idx = 0;
	size_t tlen = 0;
	const char * argp;

	for (;;) {
		size_t arglen;

		argp = argv[idx];
		if (argp == NULL)
			break;
		if (argp[0] == '\0') {
			arglen = 3;
			argp = "\"\"";
		} else {
			arglen = strlen(argp) + 1;
		}

		idx++;
		tlen += arglen;
		fputs(argp, stderr);
		if (idx >= argc) {
			fputc('\n', stderr);
			break;
		}

		if (tlen >= 80) {
			tlen = 0;
			fputs(" \\\n\t", stderr);
		} else {
			fputc(' ', stderr);
		}
	}
	fflush(stderr);
}
