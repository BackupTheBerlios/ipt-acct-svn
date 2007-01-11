# $Id$

obj-m = ipt_ACCT.o
IPTABLES ?= /sbin/iptables
IPTABLES_LIBS ?= /lib/iptables
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_SOURCES ?= $(MODULES_DIR)/build
KDIR := $(KERNEL_SOURCES)
PREFIX ?= /usr/local

CC ?= gcc
CFLAGS ?= -O2
IPTABLES_VERSION := $(shell $(IPTABLES) --version | sed -e 's/.* v//')
CFLAGS := $(CFLAGS) -Wall -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\"

all: module lib dumper stat

module:
ifdef OLD_KERNEL
	  make -f Makefile-2.4
else
		make -C $(KDIR) M=$(PWD) modules
endif

lib: libipt_ACCT.so

libipt_ACCT.so: libipt_ACCT.o
	$(CC) -shared -o $@ $<

libipt_ACCT.o: libipt_ACCT.c ipt_ACCT.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

dumper: dump_ipt_acct

dump_ipt_acct: dump_ipt_acct.o
	$(CC) -o $@ $<

dump_ipt_acct.o: dump_ipt_acct.c ipt_ACCT.h
	$(CC) $(CFLAGS) -c -o $@ $<

stat: stat_ipt_acct

stat_ipt_acct: stat_ipt_acct.o
	$(CC) -o $@ $<

stat_ipt_acct.o: stat_ipt_acct.c ipt_ACCT.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: all
	@for d in $(IPTABLES_LIBS) $(PREFIX) $(PREFIX)/include $(PREFIX)/sbin; do \
		if [ -e $$d ]; then \
			if [ ! -d $$d ]; then \
				echo "$$d is not a directory"; \
				exit 1; \
			fi; \
		else \
			mkdir -p $$d; \
		fi; \
	done
ifdef OLD_KERNEL
	mkdir -p $(MODULES_DIR)/extra
	install -m 0664 -o root -g root ipt_ACCT.o $(MODULES_DIR)/extra/
	/sbin/depmod -a
else
	make -C $(KDIR) M=$(PWD) modules_install
endif
	install -m 755 libipt_ACCT.so $(IPTABLES_LIBS)
	install -m 644 ipt_ACCT.h $(PREFIX)/include
	install -m 755 dump_ipt_acct $(PREFIX)/sbin
	install -m 755 stat_ipt_acct $(PREFIX)/sbin

clean:
ifdef OLD_KERNEL
		make -f Makefile-2.4 clean
else
		make -C $(KDIR) M=$(PWD) clean
endif
	rm -f libipt_ACCT.o libipt_ACCT.so
	rm -f dump_ipt_acct.o dump_ipt_acct
	rm -f stat_ipt_acct.o stat_ipt_acct

