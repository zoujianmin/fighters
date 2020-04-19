#
# Created by xiaoqzye@qq.com
#
# Simple Makefile for dark-energy
#
# 2020/03/29

CC       := $(FI_TCPREFIX)gcc
CFLAGS   := -I. -I$(FI_PREFIX)/include $(FI_CFLAGS)
LDFLAGS  := $(FI_LDFLAGS)
TARGETS  := darken_un.o  libdarken.so

.PHONY : all clean install

all : $(TARGETS)

libdarken.so : dark_energy.o
	$(CC) -shared -o $@ $< $(LDFLAGS) -Wl,-soname=$@

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install : all
	mkdir -p -v $(FI_PREFIX)/include && cp -v -u dark_energy.h $(FI_PREFIX)/include/
	mkdir -p -v $(FI_PREFIX)/lib && cp -v -u libdarken.so $(FI_PREFIX)/lib/

clean :
	rm -rf $(TARGETS)

