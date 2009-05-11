# Makefile for xtruss.

prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/man
man1dir = $(mandir)/man1

INSTALL = install

CFLAGS = -Wall $(XFLAGS)

-include Makefile.local

XTRUSS_MODULES := uxxtruss x11fwd ux_x11 timing misc version tree234 proxy uxsel uxnet uxmisc pproxy nocproxy time sshdes sshrand sshsha uxnoise
XTRUSS_OBJS := $(patsubst %,%.o,$(XTRUSS_MODULES))

ALLMODULES := $(sort $(XTRUSS_MODULES))
ALLOBJS := $(patsubst %,%.o,$(ALLMODULES))
ALLDEPS := $(patsubst %,%.d,$(ALLMODULES))

BINARIES = xtruss

binaries: $(BINARIES)

xtruss: $(XTRUSS_OBJS)
	gcc $(LFLAGS) -o xtruss $(XTRUSS_OBJS)

configure: configure.ac
	aclocal
	autoconf
	@# autoheader # reinstate if we need a config.h
	automake -a --foreign

INTERNALFLAGS=#

$(ALLOBJS): %.o: %.c
	gcc $(CFLAGS) -MM $*.c > $*.d
	gcc $(CFLAGS) $(INTERNALFLAGS) -c $*.c

MANPAGES = xtruss.1

doc: $(MANPAGES)
$(MANPAGES): %.1: %.but
	halibut --man=$*.1 $*.but

clean:
	rm -f $(ALLOBJS) $(ALLDEPS) $(MANPAGES) $(BINARIES)

spotless: clean
	rm -f config.h config.h.in config.log config.status configure
	rm -f depcomp install-sh missing stamp-h1
	rm -f Makefile.in aclocal.m4 build.log
	rm -rf autom4te.cache .deps build.out

-include $(ALLDEPS)
