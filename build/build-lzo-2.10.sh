#!/bin/bash

retv=0
if [ ! -e "${FI_CONFIGURED}" ] ; then
	./configure --prefix=${FI_PREFIX} --host=${FI_HOST} CC=${FI_TCPREFIX}gcc CXX=${FI_TCPREFIX}g++ \
		CFLAGS="${FI_CFLAGS}" LDFLAGS="${FI_LDFLAGS}" --disable-nls --enable-shared=no --enable-static=yes
	retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_CONFIGURED}"
fi
[ ${retv} -ne 0 ] && exit ${retv}

if [ ! -e "${FI_COMPILED}" ] ; then
	make V=1 ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_COMPILED}"
fi
[ ${retv} -ne 0 ] && exit ${retv}

if [ ! -e "${FI_INSTALLED}" ] ; then
	make install ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_INSTALLED}"
fi
exit ${retv}

