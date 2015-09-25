Name: tvs_testsuite_dependency
Summary: TLT Validation Suite 
Version: 1.0
Release: 0
License: BSD
Group: Test
Source: %{name}-%{PACKAGE_VERSION}.%{PACKAGE_RELEASE}.tgz
BuildRoot: /var/tmp/%{name}-root
BuildRequires:tet_testsuite_dependency 
Requires:tet_testsuite_dependency 
#####################################################
## NOTE: For the most part all environment variables
##       are sourced from ./etc/TVSEnvironment, enabling
##       environment tweaks to be isolated to the one
##       file.
##
##       However, there is one exception to the rule.
##       Because I could not figure out how to use 
##       a variable in the %file section, I was forced
##       to hard code $TVS_ROOT as '/usr/tet/TVS'.  Any
##       changes to $TVS_ROOT will need to be syncronized
##       with a %file entry at the bottom of this file.

%define INSTALL_ROOT /usr/tet/TVS
%ifarch x86_pentium3
AutoReqProv: No
%endif
%description
This package provide some enhaucement for TET and is used as framework for testing 

%prep
%setup

%build

. ./etc/TVSEnvironment

make all
make install
%install
rm -fr $RPM_BUILD_ROOT

. ./etc/TVSEnvironment

mkdir -p $RPM_BUILD_ROOT/etc/init.d
cp bin/tvs $RPM_BUILD_ROOT/etc/init.d

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/bin
cp -r bin/ $RPM_BUILD_ROOT$TVS_ROOT

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/inc
cp -r inc/ $RPM_BUILD_ROOT$TVS_ROOT/

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/lib
cp -r lib/ $RPM_BUILD_ROOT$TVS_ROOT/

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/etc
cp etc/master_execute.cfg $RPM_BUILD_ROOT$TVS_ROOT/etc
cp etc/TVSListing $RPM_BUILD_ROOT$TVS_ROOT/etc
cp etc/tet_code $RPM_BUILD_ROOT$TET_ROOT


mkdir -p $RPM_BUILD_ROOT/etc
cp etc/TVSEnvironment $RPM_BUILD_ROOT/etc

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/tsets
cp -r tsets/ $RPM_BUILD_ROOT$TVS_ROOT/

mkdir -p $RPM_BUILD_ROOT$TVS_ROOT/documentation/TestPlans
cp -r documentation/ $RPM_BUILD_ROOT$TVS_ROOT/

# Just incase we did a 'cvs co' and not a 'cvs export', remove
# all of the CVS directories
rm -fR `find $RPM_BUILD_ROOT -name 'CVS'`
%post
ln /etc/init.d/tvs /etc/rc.d/rc3.d/S99tvs -sf
ln /etc/init.d/tvs /etc/rc.d/rc5.d/S99tvs -sf
grep "United" /etc/issue
if [ $? -eq 0 ];then
	chkconfig -a tvs
fi
%clean

%files
%defattr (-, root, root)
/etc/TVSEnvironment
/etc/init.d/tvs

# This has to match $TVS_ROOT!!
%{INSTALL_ROOT}
%{INSTALL_ROOT}/../tet_code
