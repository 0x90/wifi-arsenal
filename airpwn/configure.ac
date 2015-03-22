AC_INIT(airpwn, 1.4, gst@remote-exploit.org)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([802_11.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(net, libnet_build_tcp, [], AC_MSG_ERROR(libnet required))
AC_CHECK_LIB(pcap, pcap_open_live, [], AC_MSG_ERROR(libpcap required))
AC_CHECK_LIB(pcre, pcre_compile, [], AC_MSG_ERROR(libpcre required))
AC_CHECK_LIB(pthread, pthread_create, [], AC_MSG_ERROR(libpthread required))
AC_CHECK_LIB(orcon, tx80211_txpacket, [], AC_MSG_ERROR(LORCON required. Install LORCON before building airpwn.))
AC_CHECK_LIB(crypto, MD5_Init, [], AC_MSG_NOTICE(openssl required for full WEP key generation))
AC_CHECK_LIB(python2.7, PyString_FromString, [], AC_MSG_NOTICE(Python2.7 required))

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h pthread.h])
AC_CHECK_HEADERS([libnet.h pcap.h tx80211.h tx80211_packet.h openssl/md5.h], [], AC_MSG_ERROR(required header missing..))
AC_CHECK_HEADERS([python2.7/Python.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([inet_ntoa strtol])

# Build options

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
