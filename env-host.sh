#!/bin/bash

# environment variables to compile for host

export FI_RDIR="`/bin/pwd -P`"
if [ "`echo -n ${FI_RDIR} | sed -r -e 's#\s+##'`" != "${FI_RDIR}" ] ; then
	unset FI_RDIR # remove environment variable
	echo "Error, white spaces not allowed in the path of fighters project" 1>&2
else
	unset FI_TCPREFIX
	unset LD_LIBRARY_PATH
	export FI_HOST_BUILD='true'
	export FI_PREFIX=/opt/fight
	export FI_HOST='x86_64-linux-gnu'
	export FI_LDFLAGS="-L${FI_PREFIX}/lib -Wl,-rpath=${FI_PREFIX}/lib"
	export FI_CFLAGS='-Wall -O2 -fPIC -D_GNU_SOURCE'
	export PATH=/usr/bin:/usr/sbin:/bin:/sbin
fi

