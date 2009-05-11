# autoconf input for xtruss. -*- sh -*-

AC_INIT([xtruss], [6.66], [anakin@pobox.com])
AC_CONFIG_SRCDIR([uxxtruss.c])

AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL

AC_SEARCH_LIBS(connect, socket nsl)
AC_SEARCH_LIBS(gethostbyname, socket nsl resolv)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
