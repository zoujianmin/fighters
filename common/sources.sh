#!/bin/bash

# Copyright 2021 Ye Holmes <yeholmes@outlook.com>
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

lua53_config() {
    apply_patches "${FTOPDIR}/patches/lua-5.3.6" || return 1
    [ ! -e 'src/darken_un.c' ] && ln -sv "${FTOPDIR}/darkenergy/darken_un.c" ./src/
    [ ! -e 'src/darken_head.h' ] && ln -sv "${FTOPDIR}/darkenergy/darken_head.h" ./src/
    return 0
}

lua53_build() {
    make FTC_PREFIX=${FTC_PREFIX} FTC_CFLAGS="${FTC_CFLAGS}" -j1 || return 1
    make INSTALL_TOP="${FSTAGING_DIR}/usr" install
    return $?
}

fighter_clean() {
    make -j1 clean
    return $?
}

liblzo2_config() {
    ./configure --prefix=/usr --host=${FTC_HOST} CC=${FTC_CC} CXX=${FTC_CXX} \
		CFLAGS="${FTC_FLAGS}" --enable-shared=yes --enable-static=no
    return $?
}

liblzo2_build() {
    make V=1 -j1 || return 1
    make DESTDIR="${FSTAGING_DIR}" install
    return $?
}

dummy_config() {
    # nothing TODO
    return 0
}

darkenergy_build() {
    make FTC_PREFIX=${FTC_PREFIX} FTC_CFLAGS="${FTC_CFLAGS}" -j1
    return $?
}

simple_build() {
    make -j1
    return $?
}

simple_clean() {
    make -j1 clean
    return $?
}

register_source 'toolchain' \
    dummy_config simple_build simple_clean
register_source 'lzo-2.10.tar.gz' \
    liblzo2_config liblzo2_build fighter_clean
register_source 'lua-5.3.6.tar.gz' \
    lua53_config lua53_build fighter_clean
register_source 'darkenergy' \
    dummy_config darkenergy_build fighter_clean
register_source 'system' \
    dummy_config simple_build simple_clean
