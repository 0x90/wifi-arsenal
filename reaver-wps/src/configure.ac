AC_INIT(reaver, 1.4)

AC_PROG_CC
AC_LANG(C)

CFLAGS="-Wall $CFLAGS"
LDFLAGS="-ldl -lm -lpcap -lsqlite3 $LDFLAGS"

AC_CHECK_LIB(pcap, pcap_open_live, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(sqlite3, sqlite3_open, [], [echo "error: sqlite3 library not found!"; exit -1])
AC_CHECK_HEADERS([stdlib.h stdint.h string.h],[],[echo "error: missing standard header files" && exit -1])
AC_CHECK_HEADERS([pcap.h],[],[echo "error: missing sqlite3 header files" && exit -1])
AC_CHECK_HEADERS([sqlite3.h],[],[echo "error: missing sqlite3 header files" && exit -1])

cp confdefs.h config.h

AC_SUBST(target, $PACKAGE_NAME)
AC_OUTPUT(Makefile)
