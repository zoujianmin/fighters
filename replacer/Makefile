# Simple Makefile for replacer

MAKEFLAGS += -r -R
CC         = gcc
CFLAGS     = -Wall -fPIC -O2 -D_GNU_SOURCE -I.
TARGETS    = replacer replacer.o main.o

.PHONY: all clean

all: $(TARGETS)

replacer: main.o replacer.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c replacer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o replacer
