#!/bin/bash

# Created by xiaoqzye@qq.com
# Configure/Compile/Install applications for GNU/Linux
# 2020/03/22

unset LD_LIBRARY_PATH
export MYI_TDIR="`/bin/pwd -P`"
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

DL_TARDIR="${MYI_TDIR}/tarballs"
# create directory to store the source tarballs
mkdir -p "${DL_TARDIR}"

VAL_SHA256=""
function get_sha256 {
	# set global value to empty string
	VAL_SHA256=""
	if [ ! -f "$1" ] ; then
		echo "Error, not a regular file: \"$1\"." 1>&2
		return 1
	fi
	local valsum=`sha256sum -b "$1" | awk '{ print $1 }'`
	if [ -z "${valsum}" ] ; then
		echo "Error, cannot get the SHA256 checksum for \"$1\"." 1>&2
		return 2
	fi
	VAL_SHA256="${valsum}"
	return 0
}

function validate_sha256 {
	if [ ! -f "$1" ] ; then
		echo "Error, file not found: \"$1\"." 1>&2
		return 1
	fi

	get_sha256 "$1" || return 2
	if [ "${VAL_SHA256}" != "$2" ] ; then
		echo "Error, SHA256 checksums do not match: \"$1\"." 1>&2
		return 3
	fi
	return 0
}

# function to download source
function download_source {
	cd "${DL_TARDIR}" || return 1
	if [ -f "$2" ] ; then
		validate_sha256 "$2" "$3" || return 2
		echo "already downloaded: \"$2\""
		return 0
	fi

	rm -rf "$2" ; sync
	echo "downloading \"$2\"..."
	wget "$1/$2"
	if [ $? -ne 0 ] ; then
		echo "Error, failed to download \"$2\"." 1>&2
		rm -rf "$2"
		return 3
	fi
	validate_sha256 "$2" "$3" || return 4
	echo "downloaded source tarball: \"$2\""
	chmod 444 "$2"
	return 0
}

GNU_URL='http://mirrors.ustc.edu.cn/gnu'
download_source "${GNU_URL}/make" 'make-4.3.tar.gz' 'e05fdde47c5f7ca45cb697e973894ff4f5d79e13b750ed57d7b66d8defc78e19'

