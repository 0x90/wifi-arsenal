dnl @synopsis AX_BOOST_SIGNALS
dnl
dnl Test for Signals library from the Boost C++ libraries. The macro
dnl requires a preceding call to AX_BOOST_BASE. Further documentation
dnl is available at <http://randspringer.de/boost/index.html>.
dnl
dnl This macro calls:
dnl
dnl   AC_SUBST(BOOST_SIGNALS_LIB)
dnl
dnl And sets:
dnl
dnl   HAVE_BOOST_SIGNALS
dnl
dnl @category InstalledPackages
dnl @category Cxx
dnl @author Thomas Porschberg <thomas@randspringer.de>
dnl @author Michael Tindal <mtindal@paradoxpoint.com>
dnl @version 2006-06-15
dnl @license AllPermissive

AC_DEFUN([AX_BOOST_SIGNALS],
[
	AC_ARG_WITH([boost-signals],
	AS_HELP_STRING([--with-boost-signals@<:@=special-lib@:>@],
                   [use the Signals library from boost - it is possible to specify a certain library for the linker
                        e.g. --with-boost-signals=boost_signals-gcc-mt-d ]),
        [
        if test "$withval" = "no"; then
			want_boost="no"
        elif test "$withval" = "yes"; then
            want_boost="yes"
            ax_boost_user_signals_lib=""
        else
		    want_boost="yes"
        	ax_boost_user_signals_lib="$withval"
		fi
        ],
        [want_boost="no"]
	)

	if test "x$want_boost" = "xyes"; then
        AC_REQUIRE([AC_PROG_CC])
		CPPFLAGS_SAVED="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
		export CPPFLAGS

		LDFLAGS_SAVED="$LDFLAGS"
		LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"
		export LDFLAGS

        AC_CACHE_CHECK(whether the Boost::Signals library is available,
					   ax_cv_boost_signals,
        [AC_LANG_PUSH([C++])
		 AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[@%:@include <boost/signal.hpp>
											]],
                                  [[boost::signal<void ()> sig;
                                    return 0;
                                  ]]),
                           ax_cv_boost_signals=yes, ax_cv_boost_signals=no)
         AC_LANG_POP([C++])
		])
		if test "x$ax_cv_boost_signals" = "xyes"; then
			AC_DEFINE(HAVE_BOOST_SIGNALS,,[define if the Boost::Signals library is available])
			BN=boost_signals
            if test "x$ax_boost_user_signals_lib" = "x"; then
				for ax_lib in $BN $BN-$CC $BN-$CC-mt $BN-$CC-mt-s $BN-$CC-s \
                              lib$BN lib$BN-$CC lib$BN-$CC-mt lib$BN-$CC-mt-s lib$BN-$CC-s \
                              $BN-mgw $BN-mgw $BN-mgw-mt $BN-mgw-mt-s $BN-mgw-s ; do
				    AC_CHECK_LIB($ax_lib, main, [BOOST_SIGNALS_LIB="-l$ax_lib" AC_SUBST(BOOST_SIGNALS_LIB) link_signals="yes" break],
                                 [link_signals="no"])
  				done
            else
               for ax_lib in $ax_boost_user_signals_lib $BN-$ax_boost_user_signals_lib; do
				      AC_CHECK_LIB($ax_lib, main,
                                   [BOOST_SIGNALS_LIB="-l$ax_lib" AC_SUBST(BOOST_SIGNALS_LIB) link_signals="yes" break],
                                   [link_signals="no"])
                  done

            fi
			if test "x$link_signals" = "xno"; then
				AC_MSG_ERROR(Could not link against $ax_lib !)
			fi
		fi

		CPPFLAGS="$CPPFLAGS_SAVED"
    	LDFLAGS="$LDFLAGS_SAVED"
	fi
])
