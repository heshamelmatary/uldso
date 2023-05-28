# SPDX-License-Identifier: GPL-2.0
#
# (C) Copyright 2023, Greg Ungerer (gerg@kernel.org)
#

CFLAGS += -target riscv64-linux-uclibc -march=rv64imaxcheri -mabi=l64pc128 -mno-relax -g
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -fomit-frame-pointer
CFLAGS += -D$(ARCH)
CFLAGS += $(EXTRA_CFLAGS)

LDFLAGS += -Wl,--no-dynamic-linker
LDFLAGS += -Wl,-z,noexecstack
#LDFLAGS += -Wl,-s
LDFLAGS += -nostdlib

OBJS = $(ARCH).o linker.o


all: checkarch uld.so.1

checkarch:
	@if [ ! -f "$(ARCH).S" ] ; then \
		echo "ARCHITECTURE '$(ARCH)' is not supported" ; \
		return 1 ; \
	fi

uld.so.1: $(OBJS)
	$(CROSS_COMPILE) $(LDFLAGS) $(CFLAGS) -o uld.so.1 $(OBJS)

.S.o:
	$(CROSS_COMPILE) $(CFLAGS) -c $<

.c.o:
	$(CROSS_COMPILE) $(CFLAGS) -c $<

clean:
	rm -f uld.so.1 *.o

help:
	@echo 'usage: make ARCH=<arch> [clean]'
	@echo
	@echo '  ARCH=           - is one of: arm, m68k, riscv'
	@echo '  CROSS_COMPILE=  - cross compiler to use'
	@echo

