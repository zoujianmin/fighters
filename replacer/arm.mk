# Simple Makefile for replacer

MAKEFLAGS += -r -R
CC         = armv7a-linux-androideabi27-clang
CFLAGS     = -Wall -fPIC -O2 -D_GNU_SOURCE -I. -march=armv7-a
CFLAGS    += -DREPLACER_ANDROID
CFLAGS    += -DREPLACER_PIDFILE=\"/mnt/replacer.lock\"
CFLAGS    += -DREPLACER_APP=\"/system/xbin/fighter.sh\"
TARGETS    = replacer replacer.o main.o

.PHONY: all clean

all: $(TARGETS)

replacer: main.o replacer.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c replacer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o replacer
