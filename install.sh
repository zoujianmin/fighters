#!/bin/bash

# Created by xiaoqzye@qq.com
# Configure/Compile/Install applications for GNU/Linux
# 2020/03/22

# check environment variable, `FI_RDIR
if [ -z "${FI_RDIR}" ] ; then
	echo "Error, environment variable \`FI_RDIR not defined." 1>&2
	exit 1
fi

FI_BUILDDIR="${FI_RDIR}/build"
FI_DL_DIR="${FI_RDIR}/tarballs"
FI_SM_DIR="${FI_RDIR}/submodules"
FI_PATCH_DIR="${FI_RDIR}/patches"
export FI_CONFIGURED=".fighter.configured"
export FI_COMPILED=".fighter.compiled"
export FI_INSTALLED=".fighter.installed"
# create directory to store the source tarballs
[ ! -e "${FI_DL_DIR}" ] && mkdir -v "${FI_DL_DIR}"

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
	cd "${FI_DL_DIR}" || return 1
	if [ -f "$2" ] ; then
		validate_sha256 "$2" "$3" || return 2
		echo "already downloaded: \"$2\""
		return 0
	fi

	rm -rf "$2" ; sync
	echo "downloading \"$2\"..."
	wget -c --tries=32 -T 180 "$1/$2"
	if [ $? -ne 0 ] ; then
		echo "Error, failed to download \"$2\"." 1>&2
		rm -rf "$2"
		return 3
	fi
	validate_sha256 "$2" "$3" || return 4
	echo "downloaded source tarball: \"$2\""
	return 0
}

function compile_package {
	local srcDir=""
	local pkgName="$1"
	cd "${FI_BUILDDIR}" || return 1 # goto project build directory

	local preTAG=".${pkgName}.prepared"
	# determine the package directory name
	if [ -d "${FI_SM_DIR}/${pkgName}" ] ; then
		srcDir="${pkgName}"
		if [ ! -e "${preTAG}" ] ; then
			rm -rf "${srcDir}" ; sync
			echo "Copy source files: \"${srcDir}\"..."
			cp -r -p -P "${FI_SM_DIR}/${pkgName}" "${srcDir}" && touch "${preTAG}"
		fi
	elif [ ! -f "${FI_DL_DIR}/${pkgName}" ] ; then
		echo "Error, package not found: \"${pkgName}\"" 1>&2
		return 2
	else
		srcDir="${pkgName%.tar*}"
		if [ -z "${srcDir}" -o "${srcDir}" = "${pkgName}" ] ; then
			echo "Error, invalid package: \"${pkgName}\"" 1>&2
			return 3
		fi
		preTAG=".${srcDir}.prepared"
		if [ ! -e "${preTAG}" ] ; then
			rm -rf "${srcDir}" ; sync
			echo "Extracting package: \"${pkgName}\"..."
			tar -axf "${FI_DL_DIR}/${pkgName}" && touch "${preTAG}"
		fi
	fi

	cd "${srcDir}" || return 5
	local patdir="${FI_PATCH_DIR}/${srcDir}"
	if [ -d "${patdir}" ] ; then
		for patfile in "${patdir}"/*.patch ; do
			[ ! -f "${patfile}" ] && continue
			[ ! -e ".patched" ] && patch -Np1 -i "${patfile}"
		done
		unset patfile ; touch ".patched"
	fi

	local builds="../build-${srcDir}.sh"
	if [ ! -e "${builds}" ] ; then
		echo "Error, build script \"${builds}\" not found." 1>&2
		return 6
	fi

	if bash "${builds}" ; then
		echo "Successfully compiled and installed \"${pkgName}\""
		return 0
	fi
	echo "Error, failed to compile and install \"${pkgName}\"" 1>&2
	return 7
}

function download_packages {
	local retv=0
	local GNU_URL='http://mirrors.ustc.edu.cn/gnu'

	download_source "${GNU_URL}/make" 'make-4.3.tar.gz' \
		'e05fdde47c5f7ca45cb697e973894ff4f5d79e13b750ed57d7b66d8defc78e19'
	retv=$? ; [ ${retv} -ne 0 ] && return ${retv}

	download_source "http://www.oberhumer.com/opensource/lzo/download" "lzo-2.10.tar.gz" \
		'c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072'
	retv=$? ; [ ${retv} -ne 0 ] && return ${retv}

	return 0
}

# clean up the build directory
function clean {
	# just remove the prepared tag-files
	rm -rf -v "${FI_BUILDDIR}"/.*.prepared
	return 0
}

# comple packages for host
function build_for_host {
	compile_package 'make-4.3.tar.gz' || exit $?
	compile_package 'lzo-2.10.tar.gz' || exit $?
	compile_package 'python-lzo'      || exit $?
	compile_package 'mksh'            || exit $?
	compile_package 'lua-5.3.5'       || exit $?
}

function build_for_target {
	compile_package 'lzo-2.10.tar.gz' || exit $?
	compile_package 'mksh'            || exit $?
	compile_package 'lua-5.3.5'       || exit $?
}

# invoke operations given by command-line arguments
if [ -n "$1" ] ; then
	$@ ; exit $?
fi

# ensure that all the source files have downloaded
download_packages || exit $?
if [ -n "${FI_HOST_BUILD}" ] ; then
	build_for_host
else
	build_for_target
fi
exit 0
