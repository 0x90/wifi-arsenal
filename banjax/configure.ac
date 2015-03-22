AC_INIT([elc], [0.1], [s.glass@nicta.com.au])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])

# this macro is used to get the arguments supplied to the configure
# script (./configure --enable-debug) Check if we have enable debug
# support.
AC_MSG_CHECKING(enable debug)
debug_default="yes"
AC_ARG_ENABLE(debug, [--enable-debug=[no/yes] turn on debugging [default=$debug_default]],, enable_debug=$debug_default)
if test "x$enable_debug" = "xyes"; then
	CXXFLAGS="$CXXFLAGS -g -DDEBUG -O0"
AC_MSG_RESULT(yes)
else
	CXXFLAGS="$CXXFLAGS -O3"
AC_MSG_RESULT(no)
fi

# Checks for prereequisite programs
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# You what?
# AC_LANG(C++)

# Check for prerequisite libraries
AX_BOOST_BASE([1.40], , AC_MSG_ERROR([boost not found.]))
#if test "$HAS_BOOST" != "yes"; then
#	AC_MSG_ERROR([boost is required.])
#fi

AX_BOOST_SIGNALS
AX_BOOST_THREAD
AX_BOOST_UNIT_TEST_FRAMEWORK

CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"

# Check header files
AC_CHECK_HEADERS([])

# # Check required libraries
# AC_CHECK_LIB([nl], [nl_cache_free, nl_socket_alloc, nl_socket_free], ,AC_MSG_ERROR([libnl2-dev not found!]))
# AC_CHECK_LIB([nl-genl], [genl_connect, genl_ctrl_alloc_cache, genl_ctrl_search_by_name, genl_family_put], ,AC_MSG_ERROR([libnl-genl not found!]))

# Compile source files in their directories (non-recursive make)
AM_INIT_AUTOMAKE([subdir-objects])

# Generate these output files
AC_CONFIG_FILES([Makefile lib/Makefile lib/banjax.pc src/Makefile src/beacons/Makefile src/changes/Makefile src/contention/Makefile src/sender/Makefile src/icmp/Makefile src/monitor/Makefile src/tstrip/Makefile src/tsync/Makefile src/traffic/Makefile src/tscal/Makefile src/txc/Makefile src/undup/Makefile src/verify/Makefile])

AC_OUTPUT
