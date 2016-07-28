AC_INIT([Moep80211 Library], [1.0], [leclaire@in.tum.de], [libmoep80211], [http://moep80211.net])
#AC_PREREQ([2.69])

AC_PROG_CC
AC_PROG_LN_S

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AM_SILENT_RULES([yes])

AM_PROG_AR
AM_PROG_CC_C_O	# Needed for some buggy automake versions

LT_INIT


PKG_CHECK_MODULES([LIBNL], [libnl-3.0 >= 3.0 libnl-genl-3.0 >= 3.0 libnl-route-3.0 >= 3.0])

AC_SEARCH_LIBS([clock_gettime], [rt])

AC_ARG_ENABLE([examples], AS_HELP_STRING([--enable-examples], [build example programs]))
AM_CONDITIONAL([WANT_EXAMPLES], [test "x$enable_examples" = "xyes"])

AC_ARG_ENABLE([doxygen], AS_HELP_STRING([--disable-doxygen], [disable rebuilding of documentation]))
AS_IF([test "x$enable_doxygen" != "xno"], [AC_CHECK_PROGS([DOXYGEN], [doxygen])], [DOXYGEN=])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([libmoep80211.pc])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([Doxyfile])])
#AC_CONFIG_HEADERS([config.h])

AC_OUTPUT
