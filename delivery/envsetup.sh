#!/bin/bash

# Created by yeholmes@outlook.com
# Simple environment script for fighters
# 2023/12/10

build_bash() {
	local CURDIR="$PWD"
	if [ ! -d "${CURDIR}" ] ; then
		echo "Error, invalid working directory: '${CURDIR}'" 1>&2
		return 1
	fi

	local bs='build.bash'
	if [ -x "./${bs}" ] ; then
		./${bs} "$@"
		return $?
	fi

	cd ..
	local updir=".."
	while true ; do
		[ "$PWD" = "/" ] && break
		if [ -x "${updir}/${bs}" ] ; then
			cd "${CURDIR}"
			${updir}/${bs} "$@"
			return $?
		fi
		cd ..
		updir="${updir}/.."
	done

	cd "${CURDIR}"
	echo "Error, script not found: '${bs}'" 1>&2
	return 2
}

ftdel_sethost() {
	if [ -z "$1" ] ; then
		echo "Error, no 'user@host' specified." 1>&2
		return 1
	fi

	declare -x FTDEL_UHOST="$1"
	if [ -z "$2" ] ; then
		export -n FTDEL_PORTNO
		echo "FTDEL target host: ${FTDEL_UHOST}"
	else
		declare -x FTDEL_PORTNO="$2"
		echo "FTDEL target host: ${FTDEL_UHOST}:${FTDEL_PORTNO}"
	fi
	return 0
}
