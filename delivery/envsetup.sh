#!/bin/bash

# Created by yeholmes@outlook.com
# Simple environment script for fighters
# 2023/12/10

bbash() {
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

ftdel_setkey() {
	if [ -z "$1" ] ; then
		export -n FTDEL_SSHKEY
		unset -v FTDEL_SSHKEY
		echo "Fighter delivery SSH-KEY undefined."
		return 0
	fi

	local SSHKEY=$(realpath "$1")
	if [ ! -f "${SSHKEY}" ] ; then
		echo "Error, SSH-KEY not found: '$1'." 1>&2
		return 1
	fi
	declare -g -x FTDEL_SSHKEY="${SSHKEY}"
	return 0
}

ftdel_sethost() {
	if [ -z "$1" ] ; then
		echo "Error, no 'user@host' specified." 1>&2
		return 1
	fi

	declare -g -x FTDEL_HOST="$1"
	if [ -z "$2" ] ; then
		export -n FTDEL_PORT
		unset -v FTDEL_PORT
		echo "FTDEL target host: ${FTDEL_HOST}"
	else
		declare -g -x FTDEL_PORT="$2"
		echo "FTDEL target host: ${FTDEL_HOST}:${FTDEL_PORT}"
	fi
	return 0
}
