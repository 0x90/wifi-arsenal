Summary: Linux central regulatory domain agent
Name: crda
Version: 1.0.1
Release: 1
License: ISC
Group: System Enviroment/Base
Source: http://wireless.kernel.org/download/crda/crda-%version.tar.bz2
URL: http://wireless.kernel.org/en/developers/Regulatory/
Packager: Luis R. Rodriguez <mcgrof@gmail.com>
BuildRoot : /var/tmp/%{name}-buildroot
Requires: libnl, libgcrypt
BuildRequires: libnl-devel, gcc, wireless-regdb, libgcrypt-devel, m2crypto

%description
This package provides CRDA to be used by the new Linux kernel
wireless subsystem to query from userspace regulatory domains. For
more information see:
http://wireless.kernel.org/en/developers/Regulatory/

%prep
%setup
%build
make DESTDIR=%buildroot
%install
make install DESTDIR=%buildroot
%files
%doc README LICENSE
/sbin/crda
/sbin/regdbdump
/lib/udev/rules.d/85-regulatory.rules
/usr/share/man/man8/crda.8.gz
/usr/share/man/man8/regdbdump.8.gz
