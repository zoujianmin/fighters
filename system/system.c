/*
 * Copyright 2021 Ye Holmes <yeholmes@outlook.com>
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

/* System level module for Lua */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdbool.h>

#define SYSTEM_INVOKE_NOWAIT           0x1
#define SYSTEM_INVOKE_READ             0x2
#define SYSTEM_INVOKE_WRITE            0x4
#define SYSTEM_INVOKE_NULLIO           0x8

#define SYSTEM_INVOKE_WAIT_CHECK       0x1
#define SYSTEM_INVOKE_WAIT_NORMAL      0x2
#define SYSTEM_INVOKE_WAIT_FOREVER     0x4

#define SYSTEM_GET_STEAL               0x08
#define SYSTEM_RDWR_BLOCK              0x10
#define SYSTEM_RDWR_NONBLOCK           0x20
#define SYSTEM_RDWR_CLOSE              0x40

#define SYSTEM_CHILD_BUFSIZE           8192
#define SYSTEM_CHILD_BUFMAX            0x100000
#define SYSTEM_CHILD_MAX_ARGS          32
#define SYSTEM_CHILD_METANAME          "System.ChildProc"
struct childproc {
	pid_t           pid;               /* pid of child process */
	int             read_fd;           /* output file descriptor, stdout for child process */
	int             write_fd;          /* read file descriptor, stdin for child process */
	char *          argv[SYSTEM_CHILD_MAX_ARGS + 1]; /* argument array of child process */
	int             argc;              /* argument array count */
	int             eval;              /* exit status via `waitpid */
	unsigned int    running : 1;       /* indicates that child process is running */
};

static int childproc_run(struct childproc * cp, int flags) __attribute__((noinline));
static int childproc_wait(struct childproc * cp, bool hang, int wopt) __attribute__((noinline));
static void childproc_free(struct childproc * cp) __attribute__((noinline));

/* exported function for Lua interpreter */
extern int luaopen_system(lua_State * L);

static int lua_check_stack(lua_State * L, int howm)
{
	int ret;
	ret = lua_checkstack(L, howm);
	if (ret == 0) {
		fprintf(stderr, "Error, cannot allocate more slots: %d\n", howm);
		fflush(stderr);
		return -1;
	}
	return 0;
}

#ifdef PRIVATE_ISINTEGER
static int lua_isinteger(lua_State * L, int idx)
{
	int dtype;
	lua_Number l_num;
	lua_Integer l_int;

	dtype = lua_type(L, idx);
	if (dtype != LUA_TNUMBER)
		return 0;
	l_num = lua_tonumber(L, idx);
	l_int = (lua_Integer) l_num;
	return l_num == (lua_Number) l_int;
}
#endif

static int system_invoke(lua_State * L)
{
	int ret, ntop;
	int flags, type2;
	struct childproc * cp;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 8) < 0)
		return 0;

	if (ntop < 2) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid number of argument: %d", ntop);
		return 2;
	}

	type2 = lua_type(L, 2);
	if (lua_isinteger(L, 1) == 0 ||
		(type2 != LUA_TSTRING && type2 != LUA_TTABLE)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid type of argument: %d, %d",
			lua_type(L, 1), type2);
		return 2;
	}

	ret = lua_getfield(L, LUA_REGISTRYINDEX, SYSTEM_CHILD_METANAME);
	if (ret != LUA_TTABLE) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to get metatable for childproc");
		return 2;
	}

	cp = (struct childproc *) lua_newuserdata(L,
		sizeof(struct childproc));
	memset(cp, 0, sizeof(struct childproc));
	cp->read_fd = -1;
	cp->write_fd = -1;

	flags = (int) lua_tointeger(L, 1);
	if (type2 == LUA_TSTRING) {
		int idx, argc = 0;
		for (idx = 2; idx <= ntop; ++idx) {
			const char * arg;
			if (lua_type(L, idx) != LUA_TSTRING)
				break;

			arg = lua_tolstring(L, idx, NULL);
			if (arg == NULL) {
				/* impossible scenario */
				fprintf(stderr, "Error, cannot fetch string at stack[%d]!\n", idx);
				fflush(stderr);
				continue;
			}

			cp->argv[argc] = strdup(arg);
			if (cp->argv[argc] == NULL) {
				int err_n = errno;
				fprintf(stderr, "Error, strdup(%s) has failed: %s\n",
					arg, strerror(err_n));
				fflush(stderr);
				continue;
			}
			if (++argc >= SYSTEM_CHILD_MAX_ARGS)
				break;
		}
		cp->argc = argc;
	} else {
		int newtop;
		int idx, argc = 0;

		newtop = lua_gettop(L);
		for (idx = 1; idx <= SYSTEM_CHILD_MAX_ARGS; ++idx) {
			const char * arg;

			lua_pushinteger(L, idx);
			if (lua_gettable(L, 0x2) != LUA_TSTRING) {
				lua_settop(L, newtop);
				break;
			}

			arg = lua_tolstring(L, -1, NULL);
			if (arg == NULL) {
				lua_settop(L, newtop);
				break;
			}

			cp->argv[argc] = strdup(arg);
			if (cp->argv[argc] == NULL) {
				int err_n = errno;
				fprintf(stderr, "Error, strdup(%s) has failed: %s\n",
					arg, strerror(err_n));
				fflush(stderr);
				lua_settop(L, newtop);
				break;
			}

			lua_settop(L, newtop);
			if (++argc >= SYSTEM_CHILD_MAX_ARGS)
				break;
		}
		cp->argc = argc;
	}

	if (cp->argc == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "no (valid) command-line arguments given");
		childproc_free(cp);
		return 2;
	}

	if (childproc_run(cp, flags) < 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to run child process: %s", cp->argv[0]);
		childproc_free(cp);
		return 2;
	}

	if ((flags & SYSTEM_INVOKE_NOWAIT) == 0) {
		while (cp->running != 0)
			childproc_wait(cp, true, 0);
	}

	lua_rotate(L, -2, 1);
	lua_setmetatable(L, -2);
	return 1;
}

int childproc_wait(struct childproc * cp, bool hang, int wopt)
{
	pid_t pid;
	int cpst, err_n = 0;

	/* already exited */
	if (cp->running == 0)
		return 0;

again:
	cpst = 0;
	pid = waitpid(cp->pid, &cpst, wopt);
	if (pid < 0) {
		err_n = errno;
		if (err_n == EINTR && hang) {
			fprintf(stderr, "waitpid(%ld) has been interrupted, continue...\n",
				(long) cp->pid);
			fflush(stderr);
			goto again;
		}

		if (err_n == ECHILD) {
			cp->running = 0;
			cp->eval = 0; /* we've no idea about the exit status */
			return 0;
		}

		fprintf(stderr, "Error, waitpid(%ld) has failed: %s\n",
			(long) cp->pid, strerror(err_n));
		fflush(stderr);
		return -1;
	}

	if (pid == 0) {
		cp->running = 1;
		cp->eval = 0;
		return 0;
	}

	cp->running = 0;
	cp->eval = cpst;
	return 0;
}

static void close_pipe_fds(int * pfds)
{
	if (pfds[0] != -1) {
		close(pfds[0]);
		pfds[0] = -1;
	}

	if (pfds[1] != -1) {
		close(pfds[1]);
		pfds[1] = -1;
	}
}

static int fdset_block(int fd, int block)
{
	int err_n = 0;
	int ret, flags;

	ret = fcntl(fd, F_GETFL, 0);
	if (ret == -1) {
		err_n = errno;
err0:
		fprintf(stderr, "Error, fcntl(%d, status flag) has failed: %s\n",
			fd, strerror(err_n));
		fflush(stderr);
		errno = err_n;
		return -1;
	}

	flags = ret;
	if (block != 0)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;
	if (ret == flags)
		return 0;

	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1) {
		err_n = errno;
		goto err0;
	}
	return 0;
}

static int fdset_cloexec(int fd, int cloexec)
{
	int err_n = 0;
	int ret, flags;

	ret = fcntl(fd, F_GETFD, 0);
	if (ret == -1) {
		err_n = errno;
err0:
		fprintf(stderr, "Error, fcntl(%d, descriptor flag) has failed: %s\n",
			fd, strerror(err_n));
		fflush(stderr);
		errno = err_n;
		return -1;
	}

	flags = ret;
	if (cloexec != 0)
		flags |= O_CLOEXEC;
	else
		flags &= ~O_CLOEXEC;
	if (ret == flags)
		return 0;

	ret = fcntl(fd, F_SETFD, flags);
	if (ret == -1) {
		err_n = errno;
		goto err0;
	}
	return 0;
}

static int pipeset_maxsize(int fd, int maxSize)
{
	int err_n = 0;
	int curSize, ret;

	ret = fcntl(fd, F_GETPIPE_SZ, 0);
	if (ret == -1) {
		err_n = errno;
err0:
		fprintf(stderr, "Error, getpipe-sz(%d) has failed: %s\n",
			fd, strerror(err_n));
		fflush(stderr);
		return -1;
	}

	curSize = ret;
	if (curSize >= maxSize)
		return curSize;
	ret = fcntl(fd, F_SETPIPE_SZ, maxSize);
	if (ret == -1) {
		err_n = errno;
		goto err0;
	}
	return maxSize;
}

int childproc_run(struct childproc * cp, int flags)
{
	pid_t pid;
	int prfds[2];
	int pwfds[2];
	int ret, err_n;

	err_n = 0;
	prfds[0] = prfds[1] = -1;
	pwfds[0] = pwfds[1] = -1;

	if (flags & SYSTEM_INVOKE_READ) {
		ret = pipe2(prfds, O_CLOEXEC);
		if (ret != 0) {
			err_n = errno;
err0:
			fprintf(stderr, "Error, failed to create pipe: %s\n", strerror(err_n));
			fflush(stderr);
			return -1;
		}
		pipeset_maxsize(prfds[1], 0x80000); /* 512KB */
	}

	if (flags & SYSTEM_INVOKE_WRITE) {
		ret = pipe2(pwfds, O_CLOEXEC);
		if (ret != 0) {
			err_n = errno;
			close_pipe_fds(prfds);
			goto err0;
		}
	}

	pid = fork(); /* try not to use vfork, which is not good */
	if (pid < 0) {
		err_n = errno;
		close_pipe_fds(prfds);
		close_pipe_fds(pwfds);
		fprintf(stderr, "Error, failed to create child process: %s\n",
			strerror(err_n));
		fflush(stderr);
		return -2;
	}

	if (pid == 0) {
		const char * arg0;

		if (prfds[0] != -1) {
			close(prfds[0]);
			prfds[0] = -1;
		}
		if (pwfds[1] != -1) {
			close(pwfds[1]);
			pwfds[1] = -1;
		}

		if (flags & SYSTEM_INVOKE_NULLIO) {
			int nfd;
			nfd = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (nfd >= 0) {
				int error = 0;
				if (nfd != STDIN_FILENO)
					error += dup2(nfd, STDIN_FILENO) == -1;
				if (nfd != STDOUT_FILENO)
					error += dup2(nfd, STDOUT_FILENO) == -1;
				if (nfd != STDERR_FILENO)
					error += dup2(nfd, STDERR_FILENO) == -1;
				if (nfd > STDERR_FILENO)
					close(nfd);
				if (error > 0)
					_exit(90);
			} else {
				err_n = errno;
				fprintf(stderr, "Error, failed to open null device: %s\n",
					strerror(err_n));
				fflush(stderr);
			}
		}

		if (prfds[1] != -1 && prfds[1] != STDOUT_FILENO) {
			ret = dup2(prfds[1], STDOUT_FILENO);
			if (ret == -1) {
				err_n = errno;
				fprintf(stderr, "Error, failed to duplicate(%d -> %d): %s\n",
					prfds[1], STDOUT_FILENO, strerror(err_n));
				fflush(stderr);
			}
			close(prfds[1]);
			prfds[1] = -1;
		}

		if (pwfds[0] != -1 && pwfds[0] != STDIN_FILENO) {
			ret = dup2(pwfds[0], STDIN_FILENO);
			if (ret == -1) {
				err_n = errno;
				fprintf(stderr, "Error, failed to duplicate(%d -> %d): %s\n",
					pwfds[0], STDIN_FILENO, strerror(err_n));
				fflush(stderr);
			}
			close(pwfds[0]);
			pwfds[0] = -1;
		}

		fdset_cloexec(STDIN_FILENO, 0);
		fdset_cloexec(STDOUT_FILENO, 0);
		fdset_cloexec(STDERR_FILENO, 0);

		arg0 = cp->argv[0];
		if (arg0[0] == '/' || arg0[0] == '.')
			execv(arg0, cp->argv);
		else
			execvp(arg0, cp->argv);
		err_n = errno;
		fprintf(stderr, "Error, failed to invoke %s: %s\n",
			arg0, strerror(err_n));
		fflush(stderr);
		_exit(91);
	}

	if (prfds[1] != -1) {
		close(prfds[1]);
		prfds[1] = -1;
	}
	if (pwfds[0] != -1) {
		close(pwfds[0]);
		pwfds[0] = -1;
	}

	cp->pid = pid;
	cp->read_fd = prfds[0];
	cp->write_fd = pwfds[1];
	cp->eval = 0;
	cp->running = 1;
	return 0;
}

static struct childproc * childproc_get(lua_State * L, int where)
{
	int type, ntop;
	struct childproc * cp;

	ntop = lua_gettop(L);
	if (ntop < where) {
		fprintf(stderr, "Error, luastack top: %d, where: %d\n",
			ntop, where);
		fflush(stderr);
		return NULL;
	}

	type = lua_type(L, where);
	if (type != LUA_TUSERDATA) {
		fprintf(stderr, "Error, stack[%d] not userdata: %d\n",
			where, type);
		fflush(stderr);
		return NULL;
	}

	cp = (struct childproc *)
		luaL_testudata(L, where, SYSTEM_CHILD_METANAME);
	if (cp == NULL) {
		fputs("Error, failed to fetch childproc!\n", stderr);
		fflush(stderr);
		return NULL;
	}
	return cp;
}

void childproc_free(struct childproc * cp)
{
	int idx;

	if (cp->running && cp->pid > 0) {
		const char * arg0;
		arg0 = cp->argv[0];
		if (arg0 == NULL)
			arg0 = "unknown";
		fprintf(stderr, "killing child process %s, pid %ld ...\n",
			arg0, (long) cp->pid);
		fflush(stderr);
		kill(cp->pid, SIGKILL);
		childproc_wait(cp, true, 0);
	}

	if (cp->read_fd >= 0) {
		close(cp->read_fd);
		cp->read_fd = -1;
	}

	if (cp->write_fd >= 0) {
		close(cp->write_fd);
		cp->write_fd = -1;
	}

	for (idx = 0; idx < SYSTEM_CHILD_MAX_ARGS; ++idx) {
		if (cp->argv[idx] == NULL)
			continue;
		free(cp->argv[idx]);
		cp->argv[idx] = NULL;
	}

	cp->argc = 0;
	cp->eval = 0;
	cp->running = 0;
}

static int childproc_wait_lua(lua_State * L)
{
	int wmask;
	bool hang;
	struct childproc * cp;
	int ntop, wopt, option;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;

	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	wopt = SYSTEM_INVOKE_WAIT_NORMAL;
	if (ntop >= 2 && lua_isinteger(L, 2) != 0)
		wopt = (int) lua_tointeger(L, 2);

	wmask = SYSTEM_INVOKE_WAIT_CHECK | SYSTEM_INVOKE_WAIT_NORMAL | SYSTEM_INVOKE_WAIT_FOREVER;
	if (wopt != (wopt & wmask) || (wopt & (wopt - 1)) != 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid wait option: %d", wopt);
		return 2;
	}

	if (wopt & SYSTEM_INVOKE_WAIT_CHECK) {
		hang = false;
		option = WNOHANG;
	} else if (wopt & SYSTEM_INVOKE_WAIT_NORMAL) {
		hang = false;
		option = 0;
	} else { /* SYSTEM_INVOKE_WAIT_FOREVER */
		hang = true;
		option = 0;
	}

	childproc_wait(cp, hang, option);
	lua_pushboolean(L, 1);
	lua_pushboolean(L, cp->running != 0);
	return 2;
}

static int childproc_running(lua_State * L)
{
	struct childproc * cp;

	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;
	lua_pushboolean(L, cp->running != 0);
	return 1;
}

static int childproc_writefd(lua_State * L)
{
	int ntop, rval;
	struct childproc * cp;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	rval = cp->write_fd;
	if (ntop >= 1 && lua_isinteger(L, 1) &&
		lua_tointeger(L, 1) == SYSTEM_GET_STEAL) {
		cp->write_fd = -1;
	}
	lua_pushinteger(L, rval);
	return 1;
}

static int childproc_readfd(lua_State * L)
{
	int ntop, rval;
	struct childproc * cp;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	rval = cp->read_fd;
	if (ntop >= 1 && lua_isinteger(L, 1) &&
		lua_tointeger(L, 1) == SYSTEM_GET_STEAL) {
		cp->read_fd = -1;
	}
	lua_pushinteger(L, rval);
	return 1;
}

static int childproc_getpid(lua_State * L)
{
	int ntop;
	lua_Integer pid;
	struct childproc * cp;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	pid = (lua_Integer) cp->pid;
	if (ntop >= 1 && lua_isinteger(L, 1) &&
		lua_tointeger(L, 1) == SYSTEM_GET_STEAL) {
		cp->pid = 0;
		cp->running = 0;
		cp->eval = 0;
	}
	lua_pushinteger(L, pid);
	return 1;
}

static int childproc_free_lua(lua_State * L)
{
	struct childproc * cp;

	if (lua_check_stack(L, 3) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	childproc_free(cp);
	lua_pushboolean(L, 1);
	return 1;
}

static int childproc_read(lua_State * L)
{
	int ntop;
	ssize_t rl1;
	int flags, rlen;
	char * rbuf = NULL;
	struct childproc * cp;

	flags = 0;
	rlen = SYSTEM_CHILD_BUFSIZE;
	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	if (cp->read_fd == -1) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid read file descriptor");
		return 2;
	}

	if (ntop >= 1 && lua_isinteger(L, 1)) {
		rlen = (int) lua_tointeger(L, 1);
		if (rlen == 0)
			rlen = SYSTEM_CHILD_BUFSIZE;
		else if (rlen < 0 || rlen > SYSTEM_CHILD_BUFMAX) {
			lua_pushnil(L);
			lua_pushfstring(L, "read size is out of range: %d", rlen);
			return 2;
		}
	}

	if (ntop >= 2 && lua_isinteger(L, 2))
		flags = (int) lua_tointeger(L, 2);
	if (flags & SYSTEM_RDWR_BLOCK)
		fdset_block(cp->read_fd, 1);
	else if (flags & SYSTEM_RDWR_NONBLOCK)
		fdset_block(cp->read_fd, 0);

	rbuf = (char *) malloc((size_t) rlen);
	if (rbuf == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, system out of memory!");
		return 2;
	}

	errno = 0;
	rl1 = read(cp->read_fd, rbuf, (size_t) rlen);
	if (rl1 <= 0) {
		int err_n = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "read has returned %d: %s",
			(int) rl1, strerror(err_n));
		free(rbuf);
		rbuf = NULL;
		return 2;
	}

	if (flags & SYSTEM_RDWR_CLOSE) {
		close(cp->read_fd);
		cp->read_fd = -1;
	}

	lua_pushlstring(L, (const char *) rbuf, (size_t) rl1);
	free(rbuf);
	rbuf = NULL;
	return 1;
}

static int childproc_write(lua_State * L)
{
	size_t argl;
	ssize_t rl1;
	int flags, ntop;
	struct childproc * cp;
	const char * wdat = NULL;

	flags = 0;
	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	if (cp->write_fd == -1) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid write file descriptor");
		return 2;
	}

	argl = 0;
	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		wdat = lua_tolstring(L, 1, &argl);
	if (wdat == NULL || argl == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid data type for write");
		return 2;
	}

	/* write_fd is a pipe */
	pipeset_maxsize(cp->write_fd, (int) argl);

	if (ntop >= 2 && lua_isinteger(L, 2))
		flags = lua_tointeger(L, 2);
	if (flags & SYSTEM_RDWR_BLOCK)
		fdset_block(cp->write_fd, 1);
	else if (flags & SYSTEM_RDWR_NONBLOCK)
		fdset_block(cp->write_fd, 0);

	rl1 = write(cp->write_fd, wdat, argl);
	if (rl1 < 0) {
		int err_n = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "failed to write(%d, %d): %s",
			cp->write_fd, (int) argl, strerror(err_n));
		return 2;
	}

	if (rl1 != (ssize_t) argl) {
		lua_pushnil(L);
		lua_pushfstring(L, "partial write for %d: %d <=> %d",
			cp->write_fd, (int) rl1, (int) argl);
		return 2;
	}

	if (flags & SYSTEM_RDWR_CLOSE) {
		close(cp->write_fd);
		cp->write_fd = -1;
	}

	lua_pushinteger(L, (lua_Integer) rl1);
	return 1;
}

static int system_setname(lua_State * L)
{
	int ntop, ret;
	char threadName[20];
	const char * tname = NULL;

	ntop = lua_gettop(L);
	if (lua_check_stack(L, 2) < 0)
		return 0;

	if (ntop >= 1 && lua_type(L, 1) == LUA_TSTRING)
		tname = lua_tolstring(L, 1, NULL);
	if (tname == NULL || tname[0] == '\0') {
		lua_pushnil(L);
		lua_pushstring(L, "invalid thread name string");
		return 2;
	}

	memset(threadName, 0, sizeof(threadName));
	strncpy(threadName, tname, sizeof(threadName) - 1);
	ret = prctl(PR_SET_NAME, (unsigned long) threadName, 0, 0, 0);
	if (ret == -1) {
		int err_n = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "prctl(SET_NAME, %s) has failed: %s",
			threadName, strerror(err_n));
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int childproc_geteval(lua_State * L)
{
	int exst;
	struct childproc * cp;

	if (lua_check_stack(L, 2) < 0)
		return 0;
	cp = childproc_get(L, 1);
	if (cp == NULL)
		return 0;

	if (cp->running != 0) {
		lua_pushnil(L);
		lua_pushstring(L, "child process still running");
		return 2;
	}

	exst = cp->eval;
	if (WIFEXITED(exst)) {
		lua_pushinteger(L, WEXITSTATUS(exst));
		lua_pushboolean(L, 0);
		return 2;
	}
	lua_pushinteger(L, WTERMSIG(exst));
	lua_pushboolean(L, 1);
	return 2;
}

static int system_sleep(lua_State * L)
{
	struct timespec tspec;
	struct timespec rspec;
	pthread_mutex_t * mutp;
	int ret, delay, error, ntop;

	error = 0;
	mutp = NULL;
	if (lua_check_stack(L, 3) < 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 1 || lua_isinteger(L, 1) == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, invalid type of sleep second");
		return 2;
	}

	delay = lua_tointeger(L, 1);
	if (delay <= 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid sleep second: %d", delay);
		return 2;
	}

	if (ntop >= 2 && lua_type(L, 2) == LUA_TSTRING) {
		const char * mptr;
		unsigned long mutptr = 0;
		mptr = lua_tolstring(L, 2, NULL);
		if (mptr && mptr[0]) {
			errno = 0;
			mutptr = (unsigned long) strtoul(mptr, NULL, 0);
			if (mutptr == ULONG_MAX || errno != 0) {
				mutptr = 0;
				fprintf(stderr, "Error, invalid mutex pointer: %s\n", mptr);
				fflush(stderr);
			}
		}
		mutp = (pthread_mutex_t *) mutptr;
	}

	ret = mutp ? pthread_mutex_lock(mutp) : 0;
	if (__builtin_expect(ret != 0, 0)) {
		fprintf(stderr, "Error, failed to acquire mutex[%p]: %d\n", mutp, ret);
		fflush(stderr);
		abort();
	}

	tspec.tv_sec = (time_t) delay;
	tspec.tv_nsec = 0;
	rspec.tv_sec = 0;
	rspec.tv_nsec = 0;
	clock_gettime(CLOCK_BOOTTIME, &rspec);
	if (__builtin_expect(rspec.tv_nsec != 0, 1)) {
		tspec.tv_sec--;
		tspec.tv_nsec = 1000000000 - rspec.tv_nsec;
	}

	ret = nanosleep(&tspec, NULL);
	if (ret == -1)
		error = errno;

	ret = mutp ? pthread_mutex_unlock(mutp) : 0;
	if (__builtin_expect(ret != 0, 0)) {
		fprintf(stderr, "Error, failed to release mutex[%p]: %d\n", mutp, ret);
		fflush(stderr);
		abort();
	}

	lua_pushinteger(L, error);
	return 1;
}

static int system_msleep(lua_State * L)
{
	struct timespec tspec;
	pthread_mutex_t * mutp;
	int ret, delay, error, ntop;

	error = 0;
	mutp = NULL;
	if (lua_check_stack(L, 3) < 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 1 || lua_isinteger(L, 1) == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Error, invalid type of sleep msec");
		return 2;
	}

	delay = lua_tointeger(L, 1);
	if (delay <= 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "Error, invalid sleep msec: %d", delay);
		return 2;
	}

	if (ntop >= 2 && lua_type(L, 2) == LUA_TSTRING) {
		const char * mptr;
		unsigned long mutptr = 0;
		mptr = lua_tolstring(L, 2, NULL);
		if (mptr && mptr[0]) {
			errno = 0;
			mutptr = (unsigned long) strtoul(mptr, NULL, 0);
			if (mutptr == ULONG_MAX || errno != 0) {
				mutptr = 0;
				fprintf(stderr, "Error, invalid mutex pointer: %s\n", mptr);
				fflush(stderr);
			}
		}
		mutp = (pthread_mutex_t *) mutptr;
	}

	ret = mutp ? pthread_mutex_lock(mutp) : 0;
	if (__builtin_expect(ret != 0, 0)) {
		fprintf(stderr, "Error, failed to acquire mutex[%p]: %d\n", mutp, ret);
		fflush(stderr);
		abort();
	}

	tspec.tv_sec = (time_t) (delay / 1000);
	tspec.tv_nsec = (long) (1000000 * (delay % 1000));
	ret = nanosleep(&tspec, NULL);
	if (ret == -1)
		error = errno;

	ret = mutp ? pthread_mutex_unlock(mutp) : 0;
	if (__builtin_expect(ret != 0, 0)) {
		fprintf(stderr, "Error, failed to release mutex[%p]: %d\n", mutp, ret);
		fflush(stderr);
		abort();
	}

	lua_pushinteger(L, error);
	return 1;
}

static int system_uptime(lua_State * L)
{
	int ret, error;
	struct timespec tspec;

	if (lua_check_stack(L, 3) < 0)
		return 0;

	tspec.tv_sec = 0;
	tspec.tv_nsec = 0;
	ret = clock_gettime(CLOCK_BOOTTIME, &tspec);
	if (ret == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to get system uptime: %s\n",
			strerror(error));
		fflush(stderr);
	}

	lua_pushinteger(L, (lua_Integer) tspec.tv_sec);
	lua_pushinteger(L, (lua_Integer) tspec.tv_nsec);
	return 2;
}

static int system_tcpsock(int * sockp, int ipv6)
{
	int error;
	int sockfd;

	sockfd = *sockp;
	if (sockfd != -1) {
		close(sockfd);
		*sockp = -1;
	}

	sockfd = socket(ipv6 ? AF_INET6 : AF_INET,
		SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockfd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to create TCP socket: %s\n",
			strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}

	fdset_block(sockfd, 0);
	*sockp = sockfd;
	return 0;
}

static int system_tcpconn(const char * ipaddr, int portno,
	const void * ipv4addr, const void * ipv6addr, int timeout)
{
	int sockfd;
	int ret, error;
	socklen_t socklen;
	struct sockaddr_in v4addr;
	struct sockaddr_in6 v6addr;

	error = 0;
	sockfd = -1;
	socklen = 0;
	memset(&v4addr, 0, sizeof(v4addr));
	v4addr.sin_family = AF_INET;
	v4addr.sin_port = htons((unsigned short) portno);

	memset(&v6addr, 0, sizeof(v6addr));
	v6addr.sin6_family = AF_INET6;
	v6addr.sin6_port = htons((unsigned short) portno);

	if (ipaddr != NULL) {
		if (inet_pton(AF_INET, ipaddr, (void *) &v4addr.sin_addr) == 1) {
			socklen = sizeof(v4addr);
			system_tcpsock(&sockfd, 0);
		} else if (inet_pton(AF_INET6, ipaddr, (void *) &v6addr.sin6_addr) == 1) {
			socklen = sizeof(v6addr);
			system_tcpsock(&sockfd, 1);
		} else {
			error = EADDRNOTAVAIL;
			goto err0;
		}
	}

	if (socklen)
		goto docon;

	if (ipv4addr != NULL) {
		const struct sockaddr_in * addrp;
		addrp = (const struct sockaddr_in *) ipv4addr;

		socklen = sizeof(v4addr);
		v4addr.sin_addr = addrp->sin_addr;
		system_tcpsock(&sockfd, 0);
	} else if (ipv6addr != NULL) {
		const struct sockaddr_in6 * addrp;
		addrp = (const struct sockaddr_in6 *) ipv6addr;

		socklen = sizeof(v6addr);
		v6addr.sin6_addr = addrp->sin6_addr;
		system_tcpsock(&sockfd, 1);
	} else {
		error = EADDRNOTAVAIL;
		goto err0;
	}

docon:
	if (sockfd == -1) {
		error = EBADF;
		goto err0;
	}

	do {
		const struct sockaddr * addrp;
		addrp = (const struct sockaddr *) &v4addr;
		if (socklen != sizeof(v4addr))
			addrp = (const struct sockaddr *) &v6addr;
		errno = 0;
		ret = connect(sockfd, addrp, socklen);
		error = errno;
	} while (0);

	if (ret == 0) {
		error = 0;
		goto err0;
	}

	if (error == ECONNREFUSED)
		goto err0;
	if (error == EINPROGRESS) {
		int err_n, serror;
		struct pollfd tfd;
again:
		tfd.fd = sockfd;
		tfd.events = POLLOUT | POLLERR | POLLPRI;
		tfd.revents = 0;

		errno = 0;
		ret = poll(&tfd, 1, timeout);
		if (ret == 0) {
			error = ETIMEDOUT;
			goto err0;
		}
		if (ret == -1) {
			err_n = errno;
			if (err_n == EINTR)
				goto again;

			fprintf(stderr, "Error, poll on TCP connect has failed: %s\n",
				strerror(err_n));
			fflush(stderr);
			error = err_n;
			goto err0;
		}

		serror = 0;
		socklen = sizeof(serror);
		ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &serror, &socklen);
		if (ret == -1) {
			err_n = errno;
			fprintf(stderr, "Error, failed to retrieve socket error: %s\n",
				strerror(err_n));
			fflush(stderr);
			error = err_n;
			goto err0;
		}
		error = serror;
	} else if (error != ENETUNREACH) {
		fprintf(stderr, "Error, TCP connect has failed: %s\n",
			strerror(error));
		fflush(stderr);
	}

err0:
	if (sockfd != -1)
		close(sockfd);
	return error;
}

static int system_tcpcheck(lua_State * L)
{
	const char * hostip;
	struct addrinfo * i_info;
	struct addrinfo * a_info;
	int ntop, timeo, portn, rval;

	rval = 0;
	timeo = 2500; /* 2500 milliseconds */
	i_info = a_info = NULL;
	if (lua_check_stack(L, 3) < 0)
		return 0;
	ntop = lua_gettop(L);
	if (ntop < 2 ||
		lua_type(L, 1) != LUA_TSTRING ||
		lua_isinteger(L, 2) == 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid type of arguments: %d, %d",
			lua_type(L, 1), lua_type(L, 2));
		return 2;
	}

	hostip = lua_tolstring(L, 1, NULL);
	portn = lua_tointeger(L, 2);
	if (hostip == NULL || hostip[0] == '\0' || portn <= 0 || portn >= 0xFFFF) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid host-ip or port-number: %d", portn);
		return 2;
	}

	if (ntop >= 3 && lua_isinteger(L, 3))
		timeo = lua_tointeger(L, 3);

	rval = system_tcpconn(hostip, portn, NULL, NULL, timeo);
	if (rval != EADDRNOTAVAIL) {
		lua_pushinteger(L, rval);
		return 1;
	}

	a_info = NULL;
	rval = getaddrinfo(hostip, NULL, NULL, &a_info);
	if (rval != 0) {
		if (a_info != NULL) {
			freeaddrinfo(a_info);
			a_info = NULL;
		}
		lua_pushinteger(L, rval);
		return 1;
	}

	rval = EADDRNOTAVAIL;
	for (i_info = a_info; i_info != NULL; i_info = i_info->ai_next) {
		int error;
		if (i_info->ai_addrlen == sizeof(struct sockaddr_in)) {
			error = system_tcpconn(NULL, portn, i_info->ai_addr, NULL, timeo);
			rval = error;
			if (error == 0 || error == ECONNREFUSED)
				break;
		} else if (i_info->ai_addrlen == sizeof(struct sockaddr_in6)) {
			error = system_tcpconn(NULL, portn, NULL, i_info->ai_addr, timeo);
			rval = error;
			if (error == 0 || error == ECONNREFUSED)
				break;
		} else {
			rval = EADDRNOTAVAIL;
			fprintf(stderr, "Error, invalid ipaddr length: %d\n",
				(int) i_info->ai_addrlen);
			fflush(stderr);
		}
	}

	if (a_info != NULL) {
		freeaddrinfo(a_info);
		a_info = NULL;
	}
	lua_pushinteger(L, rval);
	return 1;
}

static const struct luaL_Reg system_funcs[] = {
	{ "invoke",         system_invoke },
	{ "setname",        system_setname },
	{ "sleep",          system_sleep },
	{ "msleep",         system_msleep },
	{ "uptime",         system_uptime },
	{ "tcpcheck",       system_tcpcheck },
	{ NULL,             NULL },
};

static const struct luaL_Reg childproc_methods[] = {
	{ "getpid",         childproc_getpid },
	{ "wait",           childproc_wait_lua },
	{ "running",        childproc_running },
	{ "readfd",         childproc_readfd },
	{ "writefd",        childproc_writefd },
	{ "read",           childproc_read },
	{ "write",          childproc_write },
	{ "geteval",        childproc_geteval },
	{ "drop",           childproc_free_lua },
	{ "__gc",           childproc_free_lua },
	{ NULL,             NULL }
};

int luaopen_system(lua_State * L)
{
	luaL_newmetatable(L, SYSTEM_CHILD_METANAME);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, childproc_methods, 0);

	luaL_checkversion(L);
	lua_createtable(L, 0,
		sizeof(system_funcs) / sizeof(system_funcs[0]) + 0xb + 0x1);
	luaL_setfuncs(L, system_funcs, 0);

	lua_pushinteger(L, SYSTEM_INVOKE_NOWAIT);
	lua_setfield(L, -2, "INVOKE_NOWAIT");

	lua_pushinteger(L, SYSTEM_INVOKE_READ);
	lua_setfield(L, -2, "INVOKE_READ");

	lua_pushinteger(L, SYSTEM_INVOKE_WRITE);
	lua_setfield(L, -2, "INVOKE_WRITE");

	lua_pushinteger(L, SYSTEM_INVOKE_NULLIO);
	lua_setfield(L, -2, "INVOKE_NULLIO");

	lua_pushinteger(L, SYSTEM_INVOKE_WAIT_CHECK);
	lua_setfield(L, -2, "INVOKE_WAIT_CHECK");

	lua_pushinteger(L, SYSTEM_INVOKE_WAIT_NORMAL);
	lua_setfield(L, -2, "INVOKE_WAIT_NORMAL");

	lua_pushinteger(L, SYSTEM_INVOKE_WAIT_FOREVER);
	lua_setfield(L, -2, "INVOKE_WAIT_FOREVER");

	lua_pushinteger(L, SYSTEM_GET_STEAL);
	lua_setfield(L, -2, "GET_STEAL");

	lua_pushinteger(L, SYSTEM_RDWR_BLOCK);
	lua_setfield(L, -2, "RDWR_BLOCK");

	lua_pushinteger(L, SYSTEM_RDWR_NONBLOCK);
	lua_setfield(L, -2, "RDWR_NONBLOCK");

	lua_pushinteger(L, SYSTEM_RDWR_CLOSE);
	lua_setfield(L, -2, "RDWR_CLOSE");
	return 1;
}
