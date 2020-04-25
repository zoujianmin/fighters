/*
 * Created by xiaoqzye@qq.com
 *
 * System/Posix Module for Lua
 *
 * 2020/04/19
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define SYSP_SYSTEM_OUTPUT     0x01         /* request output from child process */
#define SYSP_SYSTEM_NOWAIT     0x02         /* do not wait for child process to exit */
#define SYSP_SYSTEM_NOSTDIO    0x04         /* redirect stdio file descriptors to `/dev/null */
#define SYSP_SYSTEM_MASK       0x07
#define SYSP_MIN_BUFSIZE       0x002000     /* minimum output buffer length: 8KB */
#define SYSP_MAX_BUFSIZE       0x7FFFFF     /* maximum output buffer length: 8MB - 1byte */
#define SYSP_MAX_ARGV          0x10         /* 16 arguments at most */
#define SYSP_WAIT_NOHANG       0x1          /* specify NOHANG in syscall for waitpid(...) */
#define SYSP_WAIT_AWHILE       0x2          /* hang on waitpid(...), but don't insist */

static int sysp_check_stdio(int force);
static void sysp_close_fds(int pfds[0x2]);
static int sysp_pipe_size(int fdp, int newSize);
static int sysp_cloexec(int spfd, int set_cloexec);
static unsigned char * sysp_read(int sysFd, int * readLen, int * iseof);
static int sysp_waitpid(pid_t psys, int waitopt, int * exval, int * running);
static pid_t sysp_execv(int eflag, const char *args[], int * outFd, int pipeSize);

static int sysp_system(lua_State * L)
{
	pid_t sysp;
	int argc, typi, readFD;
	int ntop, flags, outSize, isNum;
	const char *argv[SYSP_MAX_ARGV + 0x1];

	if (lua_checkstack(L, 3) == 0)
		/* not enough stack slots */
		return 0;

	/* get the number of arguments */
	ntop = lua_gettop(L);
	if (ntop < 0x2) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid number of arguments");
		return 2;
	}

	/* check the type of first argument */
	if (lua_type(L, 1) != LUA_TNUMBER) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid type of system flag");
		return 2;
	}

	isNum = 0;
	/* fetch the first argument, flags */
	flags = (int) lua_tointegerx(L, 0x1, &isNum);
	if (isNum == 0 || flags < 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid system flag: %d", flags);
		return 2;
	}

	/* get the output buffer size */
	outSize = (flags >> 0x8) & SYSP_MAX_BUFSIZE;
	flags &= SYSP_SYSTEM_MASK;
	if (outSize < SYSP_MIN_BUFSIZE)
		outSize = SYSP_MIN_BUFSIZE;

	/* clear the arguments array */
	for (argc = 0; argc <= SYSP_MAX_ARGV; ++argc)
		argv[argc] = NULL;

	argc = 0; /* number of string arguments */
	typi = lua_type(L, 2);
	if (typi == LUA_TSTRING) {
		int idx, typj;
		for (idx = 2; idx <= ntop; ++idx) {
			typj = lua_type(L, idx);
			if (typj != LUA_TSTRING) {
				lua_pushnil(L);
				lua_pushfstring(L, "invalid type of argument[%d]: %d", idx, typj);
				return 2;
			}
			argv[argc] = lua_tolstring(L, idx, NULL);
			if (argv[argc] == NULL) {
				lua_pushnil(L);
				lua_pushfstring(L, "cannot fetch argument at %d", idx);
				return 2;
			}
			if (++argc >= SYSP_MAX_ARGV)
				break;
		}
	} else if (typi == LUA_TTABLE) {
		int idx, typj;
		for (idx = 0; idx < SYSP_MAX_ARGV; ++idx) {
			typj = lua_geti(L, 2, idx + 1);
			if (typj != LUA_TSTRING) {
				lua_settop(L, ntop);
				break;
			}
			argv[argc] = lua_tolstring(L, -1, NULL);
			lua_settop(L, ntop);
			if (argv[argc] == NULL) {
				lua_pushnil(L);
				lua_pushstring(L, "failed to fetch argument in table");
				return 2;
			}
			argc++;
		}
	} else {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid type of second argument: %d", typi);
		return 2;
	}

	if (argc == 0) { /* check the number of child process array */
		lua_pushnil(L);
		lua_pushstring(L, "no arguments given in system");
		return 2;
	}

	readFD = -1;
	sysp = sysp_execv(flags, argv, (flags & SYSP_SYSTEM_OUTPUT) ? &readFD : NULL, outSize);
	if (sysp < 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "failed to run \"%s\"", argv[0]);
		return 2;
	}

	/* check if we need to wait for child process to exit */
	if (flags & SYSP_SYSTEM_NOWAIT) {
		lua_pushboolean(L, 0x1);
		lua_pushinteger(L, sysp);
		if (flags & SYSP_SYSTEM_OUTPUT) {
			lua_pushinteger(L, readFD);
			return 3;
		}
		return 2;
	}

	/* wait for the death of child process */
	argc = typi = 0;
	ntop = sysp_waitpid(sysp, 0, &argc, &typi);
	if (ntop < 0) {
		if (readFD != -1) {
			close(readFD);
			readFD = -1;
		}
		lua_pushnil(L);
		lua_pushfstring(L, "failed to wait for child process: %d", (int) sysp);
		return 2;
	}

	/* okay, now child process has exited */
	if (readFD != -1) {
		int iseof = 0;
		unsigned char * pdat;
		pdat = sysp_read(readFD, &outSize, &iseof);
		if (pdat == NULL && iseof == 0) {
			lua_pushnil(L);
			lua_pushfstring(L, "failed to read stdout from child process");
			close(readFD);
			return 2;
		}

		close(readFD);
		lua_pushboolean(L, 0x1);
		lua_pushinteger(L, argc);
		if (pdat != NULL) {
			lua_pushlstring(L, (const char *) pdat, (size_t) outSize);
			free(pdat);
			return 3;
		}
		return 2;
	}

	lua_pushboolean(L, 0x1);
	lua_pushinteger(L, argc);
	return 2;
}

static int sysp_waitpid_(lua_State * L)
{
	pid_t rpid;
	int exst, running;
	int ntop, flags, isInt;

	if (lua_checkstack(L, 3) == 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 0x2) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid number of arguments: %d", ntop);
		return 2;
	}

	rpid = -1;
	isInt = 0;
	if (lua_type(L, 1) == LUA_TNUMBER)
		rpid = (pid_t) lua_tointegerx(L, 0x1, &isInt);
	if (isInt == 0 || rpid <= 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, incorrect PID given");
		return 2;
	}

	isInt = flags = 0;
	if (lua_type(L, 2) == LUA_TNUMBER)
		flags = (int) lua_tointegerx(L, 0x2, &isInt);
	if (isInt == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, wait option not given");
		return 2;
	}

	exst = running = 0;
	ntop = sysp_waitpid(rpid, flags, &exst, &running);
	if (ntop < 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, waitpid(%d) has failed", (int) rpid);
		return 2;
	}

	lua_pushboolean(L, 0x1);
	lua_pushboolean(L, running != 0);
	if (running == 0) {
		lua_pushinteger(L, exst);
		return 3;
	}
	return 2;
}

static int sysp_close_(lua_State *L)
{
	int pfd, ntop, idx, jdx;

	if (lua_checkstack(L, 2) == 0)
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 0x1) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, no argument found");
		return 2;
	}

	jdx = 0;
	for (idx = 0x1; idx <= ntop; ++idx) {
		int isInt;
		if (lua_type(L, idx) != LUA_TNUMBER)
			continue;

		isInt = 0;
		pfd = (int) lua_tointegerx(L, idx, &isInt);
		if (isInt == 0)
			continue;
		if (pfd < 0)
			continue;
		jdx += (close(pfd) == 0);
	}

	lua_pushinteger(L, jdx);
	return 1;
}

static int sysp_read_(lua_State * L)
{
	unsigned char * pdat;
	int ntop, ret, pfd, readLen, iseof;

	if (lua_checkstack(L, 0x3) == 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 0x2) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, invalid number of argument");
		return 2;
	}

	ret = pfd = 0;
	if (lua_type(L, 0x1) == LUA_TNUMBER)
		pfd = (int) lua_tointegerx(L, 0x1, &ret);
	if (ret == 0 || pfd < 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, file descriptor not given");
		return 2;
	}

	ret = readLen = 0;
	if (lua_type(L, 0x2) == LUA_TNUMBER)
		readLen = (int) lua_tointegerx(L, 0x2, &ret);
	if (ret == 0 || readLen <= 0 || readLen > SYSP_MAX_BUFSIZE) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid read length: %d", readLen);
		return 2;
	}

	iseof = 0;
	ret = readLen;
	pdat = sysp_read(pfd, &ret, &iseof);
	if (pdat == NULL && iseof == 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, failed to read file descriptor: %d", pfd);
		return 2;
	}

	lua_pushinteger(L, ret);
	if (pdat != NULL) {
		lua_pushlstring(L, (const char *) pdat, (size_t) ret);
		free(pdat);
		return 2;
	}
	return 1;
}

static const luaL_Reg sysp_regs[] = {
	{ "read",         sysp_read_       },
	{ "close",        sysp_close_      },
	{ "waitpid",      sysp_waitpid_    },
	{ "system",       sysp_system      },
	{ NULL,           NULL             },
};

int luaopen_sysp(lua_State * L)
{
	luaL_checkversion(L);
	lua_createtable(L, 0, 11);
	luaL_setfuncs(L, sysp_regs, 0);

	/* 1 */
	lua_pushinteger(L, SYSP_SYSTEM_OUTPUT);
	lua_setfield(L, -2, "SYSTEM_OUTPUT");

	/* 2 */
	lua_pushinteger(L, SYSP_SYSTEM_NOWAIT);
	lua_setfield(L, -2, "SYSTEM_NOWAIT");

	/* 3 */
	lua_pushinteger(L, SYSP_SYSTEM_NOSTDIO);
	lua_setfield(L, -2, "SYSTEM_NOSTDIO");

	/* 4 */
	lua_pushinteger(L, SYSP_MIN_BUFSIZE);
	lua_setfield(L, -2, "MIN_BUFSIZE");

	/* 5 */
	lua_pushinteger(L, SYSP_MAX_BUFSIZE);
	lua_setfield(L, -2, "MAX_BUFSIZE");

	/* 6 */
	lua_pushinteger(L, SYSP_WAIT_NOHANG);
	lua_setfield(L, -2, "WAIT_NOHANG");

	/* 7 */
	lua_pushinteger(L, SYSP_WAIT_AWHILE);
	lua_setfield(L, -2, "WAIT_AWHILE");
	return 1;
}

pid_t sysp_execv(int eflag, const char *args[], int * outFd, int pipeSize)
{
	pid_t sysp;
	int ret, errN, stdfd1[2];

	stdfd1[0] = stdfd1[1] = -1;
	sysp_check_stdio(0); /* check if any standard file descriptor missing */
	if (outFd != NULL) {
		/* create pipe for child process */
		ret = pipe2(stdfd1, O_CLOEXEC | O_NONBLOCK);
		if (ret != 0) {
			errN = errno;
			fprintf(stderr, "Error, failed to create pipe: %s\n", strerror(errN));
			fflush(stderr);
			errno = errN;
			return -1;
		}
		/* reset pipe buffer size */
		sysp_pipe_size(stdfd1[0], pipeSize);
		sysp_pipe_size(stdfd1[1], pipeSize); /* is it really necessary ? */
	}

	sysp = fork(); /* fork child process */
	if (sysp < 0) {
		errN = errno;
		sysp_close_fds(stdfd1);
		fprintf(stderr, "Error, failed to create child process: %s\n", strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}

	if (sysp == 0) {
		/* child proess starts running here */
		if (eflag & SYSP_SYSTEM_NOSTDIO)
			sysp_check_stdio(0x1);

		if (outFd != NULL) {
			close(stdfd1[0]); stdfd1[0] = -1;
			if (stdfd1[1] != STDOUT_FILENO) { /* always true? */
				ret = dup2(stdfd1[1], STDOUT_FILENO);
				if (ret < 0) {
					errN = errno;
					fprintf(stderr, "Error, cannot duplicate file descriptor: %s\n", strerror(errN));
					fflush(stderr);
					_exit(90);
				}
				close(stdfd1[1]); stdfd1[1] = -1;
			}
			sysp_cloexec(STDOUT_FILENO, 0);
		} /* outFd != NULL */

		execvp(args[0], (char * const *) args); errN = errno;
		fprintf(stderr, "Error, failed to run %s: %s\n", args[0], strerror(errN));
		fflush(stderr); _exit(91);
	}

	/* parent process continue to run here */
	if (outFd != NULL) {
		close(stdfd1[1]); stdfd1[1] = -1;
		*outFd = stdfd1[0];
	}
	return sysp;
}

int sysp_pipe_size(int fdp, int newSize)
{
	int ret, olds, errN;

	errno = 0;
	ret = fcntl(fdp, F_GETPIPE_SZ, 0);
	if (ret <= 0) {
		errN = errno;
		fprintf(stderr, "Error, failed to get pipe size: %s\n", strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}

	olds = ret;
	if (olds >= newSize)
		return olds;
	errno = 0;
	ret = fcntl(fdp, F_SETPIPE_SZ, newSize);
	if (ret < 0) {
		errN = errno;
		fprintf(stderr, "Error, failed to set pipe size: %s\n", strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}
	return olds;
}

void sysp_close_fds(int pfds[0x2])
{
	if (pfds[0] >= 0) {
		close(pfds[0]);
		pfds[0] = -1;
	}
	if (pfds[1] >= 0) {
		close(pfds[1]);
		pfds[1] = -1;
	}
}

static int sysp_check_stdio(int force)
{
	struct stat iost;
	int fdn, idx, errN;
	const char * nulldev = "/dev/null";

	fdn = open(nulldev, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fdn < 0) {
		errN = errno;
		fprintf(stderr, "Error, failed to open %s: %s\n", nulldev, strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}

	for (idx = STDIN_FILENO; idx <= STDERR_FILENO; ++idx) {
		int ret = -1;
		if (force == 0)
			ret = fstat(idx, &iost);
		if (ret < 0 && idx != fdn) {
			ret = dup2(fdn, idx);
			if (ret < 0) {
				errN = errno;
				fprintf(stderr, "Error, failed to duplicate %d -> %d: %s\n",
					fdn, idx, strerror(errN));
				fflush(stderr);
			}
			sysp_cloexec(idx, 0);
		}
	}
	if (fdn > STDERR_FILENO)
		close(fdn);
	else
		sysp_cloexec(fdn, 0);
	return 0;
}

static int sysp_cloexec(int spfd, int set_cloexec)
{
	int ret, eflag, errN;

	ret = fcntl(spfd, F_GETFD, 0);
	if (ret < 0) {
		errN = errno;
		fprintf(stderr, "Error, failed get fd status: %s\n", strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}

	eflag = ret;
	if (set_cloexec != 0)
		eflag |= FD_CLOEXEC;
	else
		eflag &= ~FD_CLOEXEC;
	if (ret == eflag)
		return 0;

	ret = fcntl(spfd, F_SETFD, eflag);
	if (ret < 0) {
		errN = errno;
		fprintf(stderr, "Error, failed set fd status: %s\n", strerror(errN));
		fflush(stderr);
		errno = errN;
		return -1;
	}
	return 0;
}

int sysp_waitpid(pid_t psys, int waitopt, int * exval, int * running)
{
	pid_t rpid;
	int wst, wopt, errN;

	/* just wait for a specific child process */
	if (psys <= 0) {
		fprintf(stderr, "Error, invalid PID in [%s]: %ld\n", __FUNCTION__, (long) psys);
		fflush(stderr);
		*exval = 1;
		*running = 0;
		return -1;
	}

	*exval = 0;
	/* let's suppose that the child process is running */
	*running = 0x1;

	wopt = 0;
	if (waitopt & SYSP_WAIT_NOHANG)
		wopt |= WNOHANG;
waiting:
	wst = 0;
	rpid = waitpid(psys, &wst, wopt);
	if (rpid < 0) {
		errN = errno;
		if (errN == EINTR) {
			if (waitopt & SYSP_WAIT_AWHILE) {
				*running = 0x1; /* child process still running */
				return 0;
			}
			fprintf(stderr, "Warning, waiting for child process: %ld\n", (long) psys);
			fflush(stderr);
			goto waiting;
		}
		if (errN == ECHILD) {
			*running = 0;
			fprintf(stderr, "You really had child process with PID %ld?\n", (long) psys);
			fflush(stderr);
			return 0;
		}
		fprintf(stderr, "Error, failed to wait child process %ld: %s\n",
			(long) psys, strerror(errN));
		fflush(stderr);
		return -1;
	}

	if (rpid == 0) {
		*exval = 0;
		*running = 0x1; /* child process still running happily */
		return 0;
	}

	/* child process has terminated */
	*running = 0;
	*exval = (WIFEXITED(wst) != 0) ? WEXITSTATUS(wst) : WTERMSIG(wst);
	return 0;
}

unsigned char * sysp_read(int sysFd, int * readLen, int * iseof)
{
	int errn;
	ssize_t rl0, rl1;
	unsigned char * pdat;

	*iseof = 0;
	rl1 = (ssize_t) *readLen;
	if (rl1 <= 0 || rl1 > SYSP_MAX_BUFSIZE) {
		fprintf(stderr, "Error, invalid read length in [%s]: %ld\n", __FUNCTION__, (long) rl1);
		fflush(stderr);
		*readLen = 0;
		return NULL;
	}

	*readLen = 0;
	pdat = (unsigned char *) malloc((size_t) (rl1 + 0x1));
	if (pdat == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return NULL;
	}

	errno = 0;
	rl0 = read(sysFd, pdat, (size_t) rl1);
	if (rl0 < 0) {
		errn = errno;
		fprintf(stderr, "Failed to read(%d): %s\n", sysFd, strerror(errn));
		fflush(stderr);
		free(pdat);
		errno = errn;
		return NULL;
	}

	/* okay, we've reached the end of file */
	if (rl0 == 0) {
		*iseof = 1;
		free(pdat);
		return NULL;
	}

	/* OK, so far so good */
	*readLen = (int) rl0;
	pdat[rl0] = (unsigned char) 0;
	return pdat;
}

