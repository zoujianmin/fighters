/*
 * Created by xiaoqzye@qq.com
 *
 * System/Posix Module for Lua
 *
 * 2020/04/19
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define SYSP_SYSTEM_OUTPUT     0x01         /* request output from child process */
#define SYSP_SYSTEM_NOWAIT     0x02         /* do not wait for child process to exit */
#define SYSP_SYSTEM_NO012      0x04         /* redirect stdio file descriptors to `/dev/null */
#define SYSP_SYSTEM_MASK       0x07
#define SYSP_MIN_BUFSIZE       0x002000     /* minimum output buffer length: 8KB */
#define SYSP_MAX_BUFSIZE       0x7FFFFF     /* maximum output buffer length: 8MB - 1byte */
#define SYSP_MAX_ARGV          0x10         /* 16 arguments at most */

static int sysp_system(lua_State * L)
{
	int argc, typi;
	int ntop, flags, outSize, isNum;
	const char *argv[SYSP_MAX_ARGV + 0x1];

	if (lua_checkstack(L, 3) == 0)
		/* not enough stack slots */
		return 0;

	ntop = lua_gettop(L);
	if (ntop < 0x2) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid number of arguments");
		return 2;
	}

	if (lua_type(L, 1) != LUA_TNUMBER) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid type of system flag");
		return 2;
	}

	isNum = 0;
	flags = (int) lua_tointegerx(L, 0x1, &isNum);
	if (isNum == 0 || flags < 0) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid system flag: %d", flags);
		return 2;
	}
	outSize = (flags >> 0x8) & 0x7FFFFF;
	flags &= SYSP_SYSTEM_MASK;
	if (outSize < SYSP_MIN_BUFSIZE)
		outSize = SYSP_MIN_BUFSIZE;

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
		for (idx = 0x1; idx <= SYSP_MAX_ARGV; ++idx) {
			typj = lua_geti(L, 2, idx);
			if (typj != LUA_TSTRING)
				break;
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

	if (argc == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "no arguments given in system");
		return 2;
	}

	for (typi = 0; typi < argc; ++typi) {
		fprintf(stdout, "ARGV[%d]:\t%s\n", typi, argv[typi]);
		fflush(stdout);
	}

	lua_pushboolean(L, 1);
	return 1;
}

static const luaL_Reg sysp_regs[] = {
	{ "system",       sysp_system },
	{ NULL,           NULL        },
};

int luaopen_sysp(lua_State * L)
{
	luaL_newlib(L, sysp_regs);
	return 1;
}

