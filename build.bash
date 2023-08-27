#!/bin/bash

# Copyright 2021, 2023 Ye Holmes <yeholmes@outlook.com>
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

# Array to hold a list of source tarballs or directories
declare -a srcList
# Associate array to hold configure functions
declare -A ftConfig
# Associate array to hold build functions
declare -A ftBuild
# Associate array to hold clean functions
declare -A ftClean
# Associate array to hold extracted source directory names
declare -A ftSrcdir
# index of first source to process
declare -i startIndex=1
# index of last source to process
declare -i endIndex=0

# declare FTOPDIR environment variable
get_topdir() {
    local topdir=`realpath -s "$1"`
    [ -n "${topdir}" ] && topdir="${topdir%/*}"
    if [ -z "${topdir}" ] ; then
        echo "Error, failed to get parent directory." 1>&2
        return 1
    fi

    if [ ! -d "${topdir}" ] ; then
        echo "Error, not a directory: \"${topdir}\"." 1>&2
        return 2
    fi
    declare -g -x FTOPDIR="${topdir}"
    return 0
}

# save current directoy to FCURDIR
declare -r -x FCURDIR="$(command pwd -L)"
# get FTOPDIR defined as early as possible
get_topdir "$0" || exit 1
# add external toolchain wrapper to PATH
export PATH=${FTOPDIR}/toolchain/bin:/usr/bin:/usr/sbin:/bin:/sbin
# tag files used for control compilation
declare -r TAG_BUILT='.tag-built'
declare -r TAG_PATCHED='.tag-patched'
declare -r TAG_CONFIG='.tag-configured'

# opensource tarball directory
declare -r FSOURCE_DIR="${FTOPDIR}/opensource"
# project target directory path
declare -r -x FTARGET_DIR="${FTOPDIR}/target"
# project target staging directory
declare -r -x FSTAGING_DIR="${FTARGET_DIR}/staging"
# project target install directory
declare -r -x FINSTALL_DIR="${FTARGET_DIR}/install"
# sources definition file
declare -r def_sources="${FTARGET_DIR}/sources.sh"
# platform definition file
declare -r def_platform="${FTARGET_DIR}/platform.sh"
# toolchain definition file
declare -r def_toolchain="${FTARGET_DIR}/toolchain.sh"

# apply patches from directory
apply_patches() {
    local pdir="$1"
    if [ ! -d "${pdir}" ] ; then
        echo "Error, not a directory: '${pdir}'" 1>&2
        return 1
    fi
    if [ -e "${TAG_PATCHED}" ] ; then
        # already patched, skipped
        return 0
    fi
    local retp=0
    local -i pcnt=0
    local pfile=""
    for pfile in "${pdir}"/*.patch ; do
        if [ -f "${pfile}" ] ; then
            patch -Np1 -i "${pfile}" ; retp=$?
            [ ${retp} -ne 0 ] && break
            pcnt+=1
        fi
    done
    [ ${retp} -ne 0 ] && return 2
    [ ${pcnt} -eq 0 ] && return 3
    touch "${TAG_PATCHED}"
    return $?
}

# check whether target definition files exist
check_target_defines() {
    if [ ! -d "${FTARGET_DIR}" ] ; then
        echo "Error, target directory not found: \"${FTARGET_DIR}\"." 1>&2
        return 1
    fi
    if [ ! -f "${def_sources}" ] ; then
        echo "Error, sources definition not found: \"${def_sources}\"." 1>&2
        return 2
    fi
    if [ ! -f "${def_platform}" ] ; then
        echo "Error, platform definition not found: \"${def_platform}\"." 1>&2
        return 3
    fi
    if [ ! -f "${def_toolchain}" ] ; then
        echo "Error, toolchain definition not found: \"${def_toolchain}\"." 1>&2
        return 4
    fi
    # create staging and install directories
    create_directory "${FSTAGING_DIR}" "${FINSTALL_DIR}" || return 5
    return 0
}

# function to check and create directory
create_directory() {
    local rval=0
    while [ -n "$1" ] ; do
        local tdir="$1"
        if [ -d "${tdir}" ] ; then
            shift 1
            continue
        fi
        mkdir -p "${tdir}" 2>/dev/null ; rval=$?
        if [ ${rval} -ne 0 ] ; then
            echo "Error, failed to create directory: '${tdir}'" 1>&2
            break
        fi
        shift 1
    done
    return ${rval}
}

# check whether the argument given is a function
check_function() {
    # check if the function name is empty
    if [ -z "$2" ] ; then
        echo "Error, empty function specified for $1" 1>&2
        return 1
    fi

    # check whether the function is a real function
    if [ "$(type -t $2)" != "function" ] ; then
        echo "Error, not a function: '$2' for $1" 1>&2
        return 2
    fi
    return 0
}

register_source_dir() {
    if [ -z "$1" ] ; then
        echo "Error, source tarball not given." 1>&2
        return 1
    fi
    if [ -z "$2" ] ; then
        echo "Error, directory for '$1' not given." 1>&2
        return 2
    fi

    declare -g -A ftSrcdir["$1"]="$2"
    return 0
}

# parent function must define local variable, `retval
fetch_source_dir() {
    local srcm="$1"
    if [ -z "${srcm}" ] ; then
        echo "Error, source tarball not given." 1>&2
        return 1
    fi

    # check `ftSrcdir associate array
    local sdir="${ftSrcdir[${srcm}]}"
    if [ -n "${sdir}" ] ; then
        retval="${sdir}"
        return 0
    fi

    # remove suffix, XXXXXX.tar.* => XXXXXX
    sdir="${srcm%.tar.*}"
    if [ -z "${sdir}" -o "${sdir}" = "${srcm}" ] ; then
        echo "Error, cannot determine directory for '${srcm}'." 1>&2
        return 2
    fi
    retval="${sdir}"
    return 0
}

# register a source package to the list, `srcList
register_source() {
    local -r srcpkg="$1"
    # check the source path
    if [ -z "${srcpkg}" ] ; then
        echo "Error, no source path given." 1>&2
        return 1
    fi

    # check the configure/build/clean functions
    check_function "${srcpkg}" "$2" || return 2
    check_function "${srcpkg}" "$3" || return 3
    check_function "${srcpkg}" "$4" || return 4

    # get the number of elements in `srcList
    local -i idx=${#srcList[@]}
    idx+=1 # increment the index
    # Add the source path to the list
    declare -g -a srcList[${idx}]="${srcpkg}"

    # Add the functions to associate arrays
    declare -g -A ftConfig["${srcpkg}"]="$2"
    declare -g -A ftBuild["${srcpkg}"]="$3"
    declare -g -A ftClean["${srcpkg}"]="$4"
    return 0
}

build_source() {
    local -r srcn="${srcList[$1]}"
    if [ -z "${srcn}" ] ; then
        echo "Error, source not found at index: $1" 1>&2
        return 1
    fi

    local retw=0
    # goto FTOPDIR directory
    cd "${FTOPDIR}" || return 2

    # define Source Build directory
    local sbdir="${srcn}"
    if [ ! -d "${sbdir}" ] ; then
        local -r tarball="${FSOURCE_DIR}/${srcn}"
        # check whether the source tarball exists
        if [ ! -f "${tarball}" ] ; then
            echo "Error, source not found: ${srcn}" 1>&2
            return 3
        fi

        # get the name of extracted directory
        local retval=""
        fetch_source_dir "${srcn}" ; retw=$?
        [ $retw -ne 0 ] && return 4

        sbdir="${retval}"
        if [ ! -d "${sbdir}" ] ; then
            # extract the source tarball
            echo "Extracting from \"${srcn}\"..."
            tar -axf "${tarball}" ; retw=$?
            if [ $retw -ne 0 ] ; then
                echo "Error, failed to extract '${srcn}'." 1>&2
                return 5
            fi
        fi

        # check again, whether the directory exists
        if [ ! -d "${sbdir}" ] ; then
            echo "Error, directory for '${srcn}' not found: \"${sbdir}\"." 1>&2
            return 6
        fi
    fi

    # goto source directory
    cd "${FTOPDIR}/${sbdir}" || return 7
    if [ -e "${TAG_CONFIG}" ] ; then
        echo "already configured: ${sbdir}, skipped"
    else
        # invoke the configuration function
        local fconf="${ftConfig[${srcn}]}"
        ${fconf} ; retw=$?
        cd "${FTOPDIR}/${sbdir}"
        if [ $retw -ne 0 ] ; then
            echo "Error, failed to configure '${sbdir}'" 1>&2
            return 8
        fi
        touch "${TAG_CONFIG}"
    fi

    local dobuild=1
    [ -e "${TAG_BUILT}" ] && dobuild=0
    [ -e ".tag-rebuild" ] && dobuild=1
    if [ ${dobuild} -eq 0 ] ; then
        echo "already built: ${sbdir}, skipped"
    else
        # invoke build function
        local fbuild="${ftBuild[${srcn}]}"
        ${fbuild} ; retw=$?
        cd "${FTOPDIR}/${sbdir}"
        if [ $retw -ne 0 ] ; then
            [ -e "${TAG_BUILT}" ] && rm -rf "${TAG_BUILT}"
            echo "Error, failed to build '${sbdir}'" 1>&2
            return 9
        fi
        touch "${TAG_BUILT}"
    fi
    return 0
}

clean_source() {
    local -r srco="${srcList[$1]}"
    if [ -z "${srco}" ] ; then
        echo "Error, source not found at index: $1" 1>&2
        return 1
    fi

    # goto FTOPDIR directory
    cd "${FTOPDIR}" || return 2

    # define Source Build directory
    local cbdir="${srco}"
    if [ ! -d "${cbdir}" ] ; then
        local -r tarball="${FSOURCE_DIR}/${srco}"
        # check whether the source tarball exists
        if [ ! -f "${tarball}" ] ; then
            echo "Error, source not found: ${srco}" 1>&2
            return 3
        fi

        # get the name of extracted directory
        local retval=""
        fetch_source_dir "${srco}" || return 4
        # update source build directory
        cbdir="${retval}"
    fi

    # check whether the directory exists
    if [ ! -d "${cbdir}" ] ; then
        echo "Warning, directory not found for '${srco}': ${cbdir}" 1>&2
        return 0
    fi

    cd "${cbdir}" || return 5
    rm -rf "${TAG_BUILT}" "${TAG_CONFIG}"
    local fclean="${ftClean[${srco}]}"
    ${fclean}
    return $?
}

fetch_build_range() {
    # get the number of elements in source list
    local -i maxnum=${#srcList[@]}

    # get the length of FTOPDIR and FCURDIR
    local -i toplen=${#FTOPDIR}
    local -i curlen=${#FCURDIR}
    if [ ${curlen} -lt ${toplen} ] ; then
        echo "Error, invalid current directory: '${FCURDIR}'" 1>&2
        return 1
    fi

    if [ "${FTOPDIR}" = "${FCURDIR}" ] ; then
        declare -g -i endIndex=${maxnum}
        return 0
    fi

    toplen+=1
    local topdir="${FCURDIR:0:${toplen}}"
    if [ "${topdir}" != "${FTOPDIR}/" ] ; then
        echo "Error, invalid current directory: '${FCURDIR}'" 1>&2
        return 2
    fi

    local srcp="${FCURDIR:${toplen}}"
    if [ -z "${srcp}" ] ; then
        echo "Error, cannot get source package path." 1>&2
        return 3
    fi

    local found=0
    local -i idx=1
    while [ ${idx} -le ${maxnum} ] ; do
        local srcq="${srcList[${idx}]}"
        if [ "${srcp}" = "${srcq}" ] ; then
            found=${idx}
            break
        fi
        if [ -d "${FTOPDIR}/${srcq}" ] ; then
            idx+=1
            continue
        fi

        local retval=""
        fetch_source_dir "${srcq}" || break
        if [ "${srcp}" = "${retval}" ] ; then
            found=${idx}
            break
        fi
        idx+=1
    done

    if [ ${found} -eq 0 ] ; then
        echo "Error, cannot build '${srcp}'" 1>&2
        return 4
    fi
    declare -g -i endIndex=${found}
    declare -g -i startIndex=${found}
    return 0
}

process_sources() {
    local -r pcmd="$1"
    local -r end=${endIndex}
    local -i idx=${startIndex}

    local retu=0
    while [ ${idx} -le ${end} ] ; do
        ${pcmd} ${idx} ; retu=$?
        [ ${retu} -ne 0 ] && break
        idx+=1
    done
    return ${retu}
}

single_command() {
    local retn=0
    local solecmd="$1"
    [ $# -gt 1 ] && echo "Warning, only one command is supported."
    if [ -z "${solecmd}" -o "${solecmd}" = "build" ] ; then
        process_sources build_source ; retn=$?
    elif [ "${solecmd}" = "buildall" ] ; then
        declare -g -i endIndex=${#srcList[@]}
        process_sources build_source ; retn=$?
    elif [ "${solecmd}" = "clean" ] ; then
        process_sources clean_source ; retn=$?
    elif [ "${solecmd}" = "cleanall" ] ; then
        declare -g -i endIndex=${#srcList[@]}
        process_sources clean_source ; retn=$?
    else
        echo "Error, unknown command: '${solecmd}'"
        retn=4
    fi
    return ${retn}
}

check_target_defines || exit 2
source "${def_toolchain}"
source "${def_platform}"
source "${def_sources}"
fetch_build_range || exit 3
single_command "$@" ; exit $?
