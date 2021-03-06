Name: ostiary
Version: 4.0
Release: 1
Source: http://ingles.homeunix.net/software/ost/%{name}-%{version}.tar.gz
URL: http://ingles.homeunix.net/software/ost/
License: GPL
Group: Applications/Internet
BuildRoot: /var/tmp/%{name}-rpmroot
Summary: Simple, Secure Remote Script Execution
AutoReqProv: no
Provides: %{name}-%{version}
Requires: ld-linux.so.2, libc.so.6
Prefix: %{_docdir}
Prefix: %{_bindir}
Prefix: %{_sysconfdir}
Vendor: Raymond Ingles

%description

Ostiary is a simple, small utility that can run a fixed set of
commands on behalf of authorized users. It is highly secure by
design, intended to be completely safe to expose to the most
hostile network.

Properly used, the only form of attack it cannot defend against is
denial-of-service; at worst it will fail closed, denying even
legitimate remote service, but otherwise not disrupting the host.

%prep
%setup

%build
./configure --prefix=%{_bindir} --sysconfdir=%{_sysconfdir} --mandir=%{_mandir}
make all

%install
mkdir -p $RPM_BUILD_ROOT/usr
make prefix=$RPM_BUILD_ROOT/usr sysconfdir=$RPM_BUILD_ROOT/etc \
       mandir=$RPM_BUILD_ROOT/usr/share/man install

%changelog
* Thu Jan 29 2004 Raymond Ingles <sorceror171@gmail.com>
  - 2.0-1: restore man page installation

* Fri Jan 23 2004 Robert Meier <eaglecoach@wwnet.com>
  - 1.93b-1: relocatable, vendor, specified requires

* Thu Jan 22 2004 Bennett Todd <bet@rahul.net>
  - 1.92b-2: fixed bugs from the previous wrap --- setup doesn't want -n,
    Makefile doesn't honor DESTDIR, no man pages in %files, added config /etc
    to %files.

* Thu Jan 22 2004 Bennett Todd <bet@rahul.net>
  - 1.91b-1: initial wrap

%files
%defattr(-,root,root)
%{_bindir}/ostiaryd
%{_bindir}/ostclient
%attr(0600,root,root) %config %{_sysconfdir}/ostiary.cfg
%doc %{_mandir}/*/*
%doc CHANGELOG COPYING CREDITS INSTALL README TODO
