#  Copyright 2021 Ye Holmes <yeholmes@outlook.com>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

MAKEFLAGS   += -r -R
CC          := gcc
LUA_DIR     := /opt/dumpTool
CFLAGS      := -Wall -D_GNU_SOURCE -fPIC -O2
CFLAGS      += -I$(LUA_DIR)/include
LDFLAGS     := -Wl,-rpath=$(LUA_DIR)/lib -L$(LUA_DIR)/lib -llua

TARGETS     := system.so
.PHONY: all clean

all: $(TARGETS)

system.so: system.c
	$(CC) -shared -o $@ $(CFLAGS) $< $(LDFLAGS)

clean:
	rm -rf *.so
