AC_INIT([dot11decrypt], [0.1], [matias.fontanini@gmail.com], [dot11decrypt], [https://github.com/mfontanini/dot11decrypt])

m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AC_PROG_CXX()
AC_LANG(C++)

AX_CXX_COMPILE_STDCXX_11(noext)

# Check for libtins headers

AC_CHECK_HEADERS([tins/handshake_capturer.h])

# Check foir libtins library

echo -n "checking for libtins... "
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <tins/crypto.h>], 
    [Tins::Crypto::WPA2Decrypter dummy])],
    [echo yes],
    [AC_MSG_ERROR([libtins is either missing or an old version is installed!])])

AC_OUTPUT(Makefile)
