#
# Created by xiaoqzye@qq.com
#
# Simple Makefile for dark-energy
#
# 2020/03/29

CC       := $(FI_TCPREFIX)gcc
CFLAGS   := -I. -I$(FI_PREFIX)/include $(FI_CFLAGS)
CFLAGS   += -DDECOMPRESS_METHOD=$(if $(DECM_OTHER),$(DECM_OTHER),0)
LDFLAGS  := $(FI_LDFLAGS)
TARGETS  := darken_un.o libdarken.so template sysp.so

.PHONY : all clean install

all : $(TARGETS)

darkenergy-template.o : darkenergy-template.c template.o
	$(CC) -c -o $@ $(CFLAGS) '-DDARKEN_HEADER="template.h"' -DDARKEN_SYMBOL=__de_template $<

template : darkenergy-template.o template.o libdarken.so
	$(CC) -o $@ $^ $(LDFLAGS)

template.o : template.sh
	ghost 0x0419 template $^
	fz2object template.fz __de_template | $(CC) $(FI_CFLAGS) -c -o $@ -x assembler -

libdarken.so : dark_energy.o
	$(CC) -shared -o $@ $< $(LDFLAGS) -Wl,-soname=$@

sysp.so : sysp.c
	$(CC) $(CFLAGS) -shared -o $@ -Wl,-soname=$@ $< $(LDFLAGS) -llua

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install : all
	mkdir -p -v $(FI_PREFIX)/include && cp -v -u dark_energy.h $(FI_PREFIX)/include/
	mkdir -p -v $(FI_PREFIX)/lib && cp -v -u libdarken.so $(FI_PREFIX)/lib/
	mkdir -p -v $(FI_PREFIX)/lib/lua && cp -v -u sysp.so ${FI_PREFIX}/lib/lua/

clean :
	rm -rf *.o $(TARGETS) *.fz template.h

