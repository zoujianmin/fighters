#!/bin/bash

# Created by xiaoqzye@qq.com
# Simply build LZO module for Python3
# 2020/03/29

retv=0
if [ ! -e "${FI_COMPILED}" ] ; then
	python3 setup.py build ; retv=$?
	[ ${retv} -eq 0 ] && touch "${FI_COMPILED}"
fi
[ ${retv} -ne 0 ] && exit ${retv}


if [ ! -e "${FI_INSTALLED}" ] ; then
	mkdir -p "${FI_PREFIX}/lib/python3" ; retv=$?
	if [ ${retv} -eq 0 ] ; then
		cp -v -u -p ./build/*/lzo.*.so "${FI_PREFIX}/lib/python3/"
		retv=$?
	fi
	[ ${retv} -eq 0 ] && touch "${FI_INSTALLED}"
fi

exit ${retv}
