#!/bin/bash

# Created by xiaoqzye@qq.com
# Configure/Compile/Install applications for GNU/Linux
# 2020/03/22

if [ -z "${FI_RDIR}" ] ; then
	echo "Error, environment variable \`FI_RDIR not defined." 1>&2
	exit 1
fi

FI_BUILDDIR="${FI_RDIR}/build"
DL_TARDIR="${FI_RDIR}/tarballs"
SM_SRCDIR="${FI_RDIR}/submodules"
export FI_CONFIGURED=".fighter.configured"
export FI_COMPILED=".fighter.compiled"
export FI_INSTALLED=".fighter.installed"
# create directory to store the source tarballs
[ ! -e "${DL_TARDIR}" ] && mkdir -v "${DL_TARDIR}"

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
	return 0
}

function comple_package {
	local srcDir=""
	local pkgName="$1"
	cd "${FI_BUILDDIR}" || return $? # goto project build directory

	local preTAG=".${pkgName}.prepared"
	# determine the package directory name
	if [ -d "${SM_SRCDIR}/${pkgName}" ] ; then
		srcDir="${pkgName}"
		if [ ! -e "${preTAG}" ] ; then
			rm -rf "${srcDir}" ; sync
			echo "Copy source files: \"${srcDir}\"..."
			cp -r -p -P "${SM_SRCDIR}/${pkgName}" "${srcDir}" && touch "${preTAG}"
		fi
	elif [ ! -f "${DL_TARDIR}/${pkgName}" ] ; then
		echo "Error, package not found: \"${pkgName}\"" 1>&2
		return 1
	else
		srcDir="${pkgName%.tar*}"
		if [ -z "${srcDir}" -o "${srcDir}" = "${pkgName}" ] ; then
			echo "Error, invalid package: \"${pkgName}\"" 1>&2
			return 2
		fi
		preTAG=".${srcDir}.prepared"
		if [ ! -e "${preTAG}" ] ; then
			rm -rf "${srcDir}" ; sync
			echo "Extracting package: \"${pkgName}\"..."
			tar -axf "${DL_TARDIR}/${pkgName}" && touch "${preTAG}"
		fi
	fi

	cd "${srcDir}" || return $?
	local builds="../build-${srcDir}.sh"
	if [ ! -e "${builds}" ] ; then
		echo "Error, build script \"${builds}\" not found." 1>&2
		return 3
	fi

	if bash "${builds}" ; then
		echo "Successfully compiled and installed \"${pkgName}\""
		return 0
	fi
	echo "Error, failed to compile and install \"${pkgName}\"" 1>&2
	return $?
}

function download_packages {
	local retv=0
	local GNU_URL='http://mirrors.ustc.edu.cn/gnu'

	download_source "${GNU_URL}/make" 'make-4.3.tar.gz' \
		'e05fdde47c5f7ca45cb697e973894ff4f5d79e13b750ed57d7b66d8defc78e19'
	retv=$? ; [ ${retv} -ne 0 ] && return ${retv}

	download_source "${GNU_URL}/bash" 'bash-5.0.tar.gz' \
		'b4a80f2ac66170b2913efbfb9f2594f1f76c7b1afd11f799e22035d63077fb4d'
	retv=$? ; [ ${retv} -ne 0 ] && return ${retv}

	download_source "http://www.oberhumer.com/opensource/lzo/download" "lzo-2.10.tar.gz" \
		'c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072'
	retv=$? ; [ ${retv} -ne 0 ] && return ${retv}

	return 0
}

download_packages || exit $?
comple_package 'make-4.3.tar.gz' || exit $?
comple_package 'bash-5.0.tar.gz' || exit $?
comple_package 'lzo-2.10.tar.gz' || exit $?

