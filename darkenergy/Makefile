#
# Created by xiaoqzye@qq.com
#
# Simple Makefile for dark-energy
#
# 2020/03/29

CC       := $(FTC_PREFIX)gcc
CFLAGS   := -I. -I$(FSTAGING_DIR)/usr/include $(FTC_CFLAGS)
LDFLAGS  := $(FTC_LDFLAGS)
TARGETS  := darken_un.o libdarken.so template

.PHONY : all clean install

all : $(TARGETS)

darkenergy-template.o : darkenergy-template.c template.o
	$(CC) -c -o $@ $(CFLAGS) '-DDARKEN_HEADER="template.h"' -DDARKEN_SYMBOL=__de_template $<

template : darkenergy-template.o template.o libdarken.so
	$(CC) -o $@ $^ $(LDFLAGS)

template.o : template.sh
	ghost 0x0419 template $^
	fz2object template.fz __de_template | $(CC) $(FTC_CFLAGS) -c -o $@ -x assembler -

libdarken.so : dark_energy.o
	$(CC) -shared -o $@ $< $(LDFLAGS) -Wl,-soname=$@

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	rm -rf *.o $(TARGETS) *.fz template.h
