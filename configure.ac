# autoconf input for xtruss. -*- sh -*-

AC_INIT([xtruss], [6.66], [anakin@pobox.com])
AC_CONFIG_SRCDIR([xtruss.c])

AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_CHECK_PROG([HALIBUT],[halibut],[yes],[no])
AM_CONDITIONAL([HAVE_HALIBUT],[test "x$HALIBUT" = "xyes"])

AC_SEARCH_LIBS(connect, socket nsl)
AC_SEARCH_LIBS(gethostbyname, socket nsl resolv)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
