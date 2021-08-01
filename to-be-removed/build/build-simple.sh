#!/bin/bash

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

