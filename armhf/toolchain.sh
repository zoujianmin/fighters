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

declare -r FTC_HOST=arm-linux-gnueabihf
declare -r FTC_PREFIX="${FTC_HOST}-"
declare -r FTC_CC="${FTC_PREFIX}gcc"
declare -r FTC_CXX="${FTC_PREFIX}g++"
declare -r FTC_STRIP="${FTC_PREFIX}strip"
declare -r FTC_AR="${FTC_PREFIX}ar"
declare -r FTC_RANLIB="${FTC_PREFIX}ranlib"
declare -r FTC_LD="${FTC_PREFIX}ld"

declare -r FTC_FLAGS="-march=armv7-a -mfloat-abi=hard -mfpu=neon-vfpv4 -Wall -fPIC -O2 -ggdb -D_GNU_SOURCE"
declare -r FTC_CFLAGS="${FTC_FLAGS}"
declare -r FTC_CXXFLAGS="${FTC_FLAGS}"
