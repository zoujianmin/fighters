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

include $(FTARGET_DIR)/target.mk

HOSTCC      := gcc
HOST_CFLAGS := -Wall -O2 -fPIC -D_GNU_SOURCE

# check for external toolchain root directory
ifeq ($(EXTCROOT),)
$(error EXTCROOT not defined)
endif
EXTC_ROOT   := $(wildcard $(EXTCROOT))
ifeq ($(EXTC_ROOT),)
$(error invalid EXTCROOT defined)
endif

# check external toolchain prefix
ifeq ($(FTC_PREFIX),)
$(error FTC_PREFIX not defined)
endif

# external toolchain compilers
EXTC_CLS    := c++ cpp g++ gcc
EXTC_BIN    := addr2line ar as c++filt dwp \
    elfedit gcc-ar gcc-nm gcc-ranlib gcov \
    gcov-dump gcov-tool gfortran gprof ld \
    ld.bfd ld.gold nm objcopy objdump \
    ranlib readelf size strings strip

TARGETS     := extc-wrapper extc-invoker \
    $(addprefix bin/$(FTC_PREFIX),$(EXTC_CLS)) \
    $(addprefix bin/$(FTC_PREFIX),$(EXTC_BIN))

.PHONY: all clean

all: $(TARGETS)

% : %.c
	$(HOSTCC) $(HOST_CFLAGS) '-DEXTC_ROOT="$(EXTC_ROOT)"' \
		$(if $(FTC_FLAGS),'-DEXTC_CFLAGS="$(FTC_FLAGS)"') \
		'-DEXTC_PREFIX="$(FTC_PREFIX)"' -o $@ $^
define external_toolchain
.PHONY: bin/$(FTC_PREFIX)$(1)
bin/$(FTC_PREFIX)$(1): $(2)
	[ -x "$(EXTC_ROOT)/bin/$(FTC_PREFIX)$(1)" ] && ln -v $$< $$@ ; exit 0
endef

$(foreach tcbin,$(EXTC_CLS),$(eval $(call external_toolchain,$(tcbin),extc-wrapper)))
$(foreach tcbin,$(EXTC_BIN),$(eval $(call external_toolchain,$(tcbin),extc-invoker)))

clean:
	rm -rf $(TARGETS)
