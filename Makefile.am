AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/unix

bin_PROGRAMS = xtruss
xtruss_SOURCES = be_misc.c callback.c conf.c errsock.c logging.c	\
marshal.c memory.c misc.c noproxy.c nullplug.c sshauxcrypt.c sshdes.c	\
sshprng.c sshrand.c sshsh256.c sshutils.c time.c timing.c tree234.c	\
utils.c version.c x11fwd.c xtruss-proxy.c xtruss-record.c		\
xtruss-trace.c xtruss.c unix/ux_x11.c unix/uxcliloop.c unix/uxcons.c	\
unix/uxfdsock.c unix/uxmisc.c unix/uxnet.c unix/uxnogtk.c		\
unix/uxnoise.c unix/uxpeer.c unix/uxpoll.c unix/uxsel.c			\
unix/uxsignal.c unix/uxutils.c unix/uxxtruss.c defs.h marshal.h		\
misc.h mpint_i.h network.h proxy.h putty.h puttymem.h puttyps.h ssh.h	\
sshbpp.h sshchan.h sshcr.h sshppl.h sshserver.h storage.h tree234.h	\
version.h xtruss-macros.h xtruss.h unix/unix.h

xtruss_LDADD = $(LIBOBJS)
man1_MANS = xtruss.1

# If Halibut is available to rebuild the man pages from their .but
# source, then man pages are treated as derived files in the obvious
# way, and deleted by 'make clean'. If Halibut is not available (the
# typical case if someone has downloaded the source archive and rerun
# mkauto.sh), the man pages are treated as source files by this
# makefile.
if HAVE_HALIBUT
BUILT_MANS = $(man1_MANS)
CLEANFILES = $(BUILT_MANS)
.SUFFIXES = .but .1
.but.1:
	halibut --man=$@ $<
doc: $(BUILT_MANS)
endif
