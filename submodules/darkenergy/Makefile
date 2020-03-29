#
# Created by xiaoqzye@qq.com
#
# Simple Makefile for dark-energy
#
# 2020/03/29

CC       := gcc
CFLAGS   := -Wall -fPIC -O3 -D_GNU_SOURCE -I.
TARGETS  := darken_un.o dark_energy.o

.PHONY : all clean

all : $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	rm -rf $(TARGETS)

