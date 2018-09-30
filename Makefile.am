bin_PROGRAMS = xtruss
xtruss_SOURCES = uxxtruss.c x11fwd.c ux_x11.c timing.c misc.c version.c \
    tree234.c proxy.c uxsel.c uxnet.c uxmisc.c pproxy.c nocproxy.c time.c \
    sshdes.c sshrand.c sshsha.c uxnoise.c
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
