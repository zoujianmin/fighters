# Simple Makefile for replacer

MAKEFLAGS += -r -R
CC         = gcc
CFLAGS     = -Wall -fPIC -O2 -D_GNU_SOURCE -I.
CFLAGS    += -DREPLACER_PIDFILE=\"/var/run/replacer.lock\"
CFLAGS    += -DREPLACER_APP=\"/opt/fighter.sh\"
TARGETS    = replacer replacer.o main.o

.PHONY: all clean

all: $(TARGETS)

replacer: main.o replacer.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c replacer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o replacer
