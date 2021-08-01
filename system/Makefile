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

include $(FTARGET_DIR)/target.mk

CFLAGS      := -Iinclude
FT_OBJS     := src/ft_ipc.o
TARGETS     := system.so libfighter.so
.PHONY: all clean

all: $(TARGETS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

libfighter.so: $(FT_OBJS)
	$(CC) -shared -o $@ -Wl,-soname=$@ $^

system.so: system.c
	$(CC) -shared -o $@ $(CFLAGS) $< -llua

clean:
	rm -rf *.so $(FT_OBJS)
