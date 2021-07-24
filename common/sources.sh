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
    apply_patches "${TOPBDIR}/patches/lua-5.3.6"
    return $?
}

lua53_build() {
    make FTC_PREFIX=${FTC_PREFIX} FTC_CFLAGS="${FTC_CFLAGS}" -j1
    return $?
}

fighter_clean() {
    make -j1 clean
    return $?
}

liblzo2_config() {
    ./configure --prefix=/usr --host=${FTC_HOST} CC=${FTC_CC} CXX=${FTC_CXX} \
		CFLAGS="${FTC_FLAGS}" --enable-shared=no --enable-static=yes
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

register_source 'lua-5.3.6.tar.gz' \
    lua53_config lua53_build fighter_clean
register_source 'lzo-2.10.tar.gz' \
    liblzo2_config liblzo2_build fighter_clean
register_source 'darkenergy' \
    dummy_config darkenergy_build fighter_clean
