#!/bin/bash

# check the installation prefix
if [ -z "${FI_PREFIX}" ] ; then
	echo "Error, \`FI_PREFIX not defined" 1>&2
	exit 1
fi

lcfg='src/luaconf.h'
if [ -n "`grep -e FI_PREFIX ${lcfg}`" ] ; then
	sed -r -e "s#FI_PREFIX#${FI_PREFIX}/#g" -i "${lcfg}"
	[ -z "${FI_HOST_BUILD}" ] && sed -r -e '/LUA_USE_READLINE/d' -i "${lcfg}"
fi

retv=0
if [ ! -e "${FI_COMPILED}" ] ; then
	make ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_COMPILED}"
fi
[ ${retv} -ne 0 ] && exit $retv

if [ ! -e "${FI_INSTALLED}" ] ; then
	make install ; retv=$?
	if [ ${retv} -eq 0 ] ; then
		cd "${FI_PREFIX}/lib" && rm -rf -v 'liblua.so' && ln -sv 'liblua.so.5.3.5' 'liblua.so'
		retv=$?
	fi
	[ ${retv} -eq 0 ] && touch "${FI_INSTALLED}"
fi
exit $retv

