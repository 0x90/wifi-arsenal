AC_INIT([edump], [1.0], [ath9k-devel@qualcomm.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/edump.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC

# Checks for libraries.
PKG_CHECK_MODULES([pciaccess],
                  [pciaccess >= 0.10.3],
		  [],
                  [AC_MSG_ERROR(libpciaccess-0.10.3 is required)])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
