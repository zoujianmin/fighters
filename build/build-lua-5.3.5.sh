#!/bin/bash

# check the installation prefix
if [ -z "${FI_PREFIX}" ] ; then
	echo "Error, \`FI_PREFIX not defined" 1>&2
	exit 1
fi

lcfg='src/luaconf.h'
if [ -n "`grep -e FI_PREFIX ${lcfg}`" ] ; then
	sed -r -e "s#FI_PREFIX#${FI_PREFIX}/#g" -i "${lcfg}"
fi

retv=0
if [ ! -e "${FI_COMPILED}" ] ; then
	make ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_COMPILED}"
fi
[ ${retv} -ne 0 ] && exit $retv

if [ ! -e "${FI_INSTALLED}" ] ; then
	make install ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_INSTALLED}"
fi
exit $retv

