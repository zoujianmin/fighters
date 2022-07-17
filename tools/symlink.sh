#!/bin/bash

# Copyright 2020 Ye Holmes <yeholmes@outlook.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Created by yeholmes@outlook.com
# Simple symbolic linking for opensource tarballs
# 2020/06/20

DESTDIR="${PWD}"
[ -n "$1" ] && DESTDIR="$1"
[ ! -d "${DESTDIR}" ] && mkdir -p "${DESTDIR}"
if [ ! -d "${DESTDIR}" ] ; then
	echo "Error, cannot create directory: \"${DESTDIR}\"" 1>&2
	exit 1
fi

SRCDIR="`readlink -f -n $0`"
[ -n "${SRCDIR}" ] && SRCDIR=`dirname "${SRCDIR}"`
if [ -z "${SRCDIR}" ] ; then
	echo "Error, tarballs directory not found." 1>&2
	exit 2
fi

function symlink_dir {
	local tarfile=""
	for tarfile in "$1"/*.tar* "$1"/*.tgz "$1"/*.zip "$1"/*bin.* \
		"$1"/rpi-firmware* ; do
		if [ -L "${tarfile}" ] ; then
			# symbolic link
			continue
		fi
		if [ ! -f "${tarfile}" ] ; then
			continue
		fi
		local bName="${tarfile##*/}"
		if [ -z "${bName}" ] ; then
			echo "Error, cannot determine file name for \"${tarfile}\"" 1>&2
			continue
		fi
		if [ -e "$2/${bName}" ] ; then
			# echo "already exists: ${bName}"
			continue
		fi
		ln -sv "${tarfile}" "$2/"
	done
	unset tarfile
}

symlink_dir "${SRCDIR}" "${DESTDIR}"
exit 0
