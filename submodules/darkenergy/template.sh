#!/bin/mksh

# Created by xiaoqzye@qq.com
# template shell script for darkenergy
# 2020/04/19

deargv=''
read_argv() {
	if [ -z "${DEARGVFD}" ] ; then
		return 1 # no argument file descriptor given
	fi
	local argv=""
	read "-u${DEARGVFD}" -N -1 argv
	if [ -z "${argv}" ] ; then
		echo "Error, failed to read from \"${DEARGVFD}\"" 1>&2
		unset DEARGVFD
		return 2
	fi
	unset DEARGVFD
	deargv="${argv}"
	return 0
}

echo 'Hello World!'
read_argv && set -- ${deargv}
idx=0
while [ -n "$1" ] ; do
	echo -e "[${idx}]:\t$1"
	shift 1
	let "idx++"
done
if [ -n "${DEOUTPFD}" ] ; then
	echo "\`DEOUTPFD: ${DEOUTPFD}"
	echo 'What the hell?' 1>&${DEOUTPFD}
fi
exit 8
