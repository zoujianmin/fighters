#!/bin/bash

# Fighter project directory
export FI_RDIR="`/bin/pwd -P`"
if [ "`echo -n ${FI_RDIR} | sed -r -e 's#\s+##g'`" != "${FI_RDIR}" ] ; then
	unset FI_RDIR # remove environment variable
	echo "Error, white spaces not allowed in the path of fighters project" 1>&2
	sleep 86400 # sleep for a day
	exit 1
fi

# Fighter prefix for host
export FI_HOST_PREFIX=/opt/fight

# environment variables to compile for host
function _fight_for_host {
	unset FI_TCPREFIX
	unset LD_LIBRARY_PATH
	export FI_HOST_BUILD='true'
	export FI_HOST='x86_64-linux-gnu'
	export FI_PREFIX=${FI_HOST_PREFIX}
	export FI_CFLAGS='-Wall -O2 -fPIC -D_GNU_SOURCE'
	export FI_LDFLAGS="-L${FI_PREFIX}/lib -Wl,-rpath=${FI_PREFIX}/lib"
	export PATH="${FI_RDIR}/host/bin:/usr/bin:/usr/sbin:/bin:/sbin"
}

function _fight_for_armv7 {
	unset FI_HOST_BUILD
	unset LD_LIBRARY_PATH
	export FI_HOST='arm-linux-gnueabihf'
	export FI_TCPREFIX="${FI_HOST}-"
	export FI_PREFIX='/system/fight32'
	export FI_LDFLAGS="-L${FI_PREFIX}/lib -Wl,-rpath=${FI_PREFIX}/lib"
	export FI_CFLAGS='-march=armv7-a -mfpu=neon-vfpv4 -Wall -O2 -fPIC -D_GNU_SOURCE'
	local toolchain='/opt/gcc-linaro-7.5.0-2019.12-x86_64_arm-linux-gnueabihf'
	export PATH="${toolchain}/bin:${FI_HOST_PREFIX}/bin:${FI_RDIR}/host/bin:/usr/bin:/usr/sbin:/bin:/sbin"
}

function _fight_for_armv8 {
	unset FI_HOST_BUILD
	unset LD_LIBRARY_PATH
	export FI_HOST='aarch64-linux-gnu'
	export FI_TCPREFIX="${FI_HOST}-"
	export FI_PREFIX='/system/fight64'
	export FI_CFLAGS='-Wall -O2 -fPIC -D_GNU_SOURCE'
	export FI_LDFLAGS="-L${FI_PREFIX}/lib -Wl,-rpath=${FI_PREFIX}/lib"
	local toolchain='/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu'
	export PATH="${toolchain}/bin:${FI_HOST_PREFIX}/bin:${FI_RDIR}/host/bin:/usr/bin:/usr/sbin:/bin:/sbin"
}

