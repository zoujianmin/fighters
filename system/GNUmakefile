# Simple Makefile for lua/system

MAKEFLAGS += -r -R
CC         = gcc
CFLAGS     = -Wall -fPIC -O2 -D_GNU_SOURCE -I/usr/include/lua5.3
TARGETS    = system.so

.PHONY: all clean

all: $(TARGETS)

system.so: system.c
	$(CC) $(CFLAGS) -shared -o $@ -Wl,-soname=$@ $<

clean:
	rm -rf *.o *.so
