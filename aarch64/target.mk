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

# disable GNU Make builtin variables and rules
MAKEFLAGS     += -r -R

# toolchain definitions:
FTC_PREFIX    := aarch64-linux-gnu-
CC            := $(FTC_PREFIX)gcc
CXX           := $(FTC_PREFIX)g++
STRIP         := $(FTC_PREFIX)strip
AR            := $(FTC_PREFIX)ar
RANLIB        := $(FTC_PREFIX)ranlib
LD            := $(FTC_PREFIX)ld

FTC_FLAGS     := -Wall -fPIC -O2 -ggdb -D_GNU_SOURCE
FTC_CFLAGS    := $(FTC_FLAGS)
FTC_CXXFLAGS  := $(FTC_FLAGS)
