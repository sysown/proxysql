# Don't try fancy stuff like debuginfo, which is useless on binary-only
# packages. Don't strip binary too
# Be sure buildpolicy set to do nothing
%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Summary: A high-performance MySQL proxy
Name: proxysql
Version: 1.2.2
Release: 1
License: GPL+
Group: Development/Tools
SOURCE0 : %{name}-%{version}.tar.gz
URL: http://www.proxysql.com/

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%build
# Empty section.

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}

# in builddir
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%post
mkdir /var/run/%{name}
chkconfig --add %{name}

%postun
rm -rf /var/run/%{name}
chkconfig --del %{name}

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/%{name}.cnf
%{_bindir}/*
%{_sysconfdir}/init.d/%{name}
/usr/share/proxysql/tools/proxysql_galera_checker.sh
/usr/share/proxysql/tools/proxysql_galera_writer.pl

%changelog
* Fri Sep 2 2016  Rene Cannao <rene.cannao@gmail.com> 1.2.2
- Second stable release of 1.2
* Tue Aug 2 2016  Rene Cannao <rene.cannao@gmail.com> 1.2.1
- First stable release of 1.2
* Mon Mar 14 2016 Rene Cannao <rene.cannao@gmail.com> 1.2.0
- First testing release of 1.2
* Sat Mar 11 2016 Rene Cannao <rene.cannao@gmail.com> 1.1.2
- Upgraded to release 1.1.2
* Sat Oct 31 2015 Rene Cannao <rene.cannao@gmail.com> 1.0.1
- Compiles 1.0.1
* Wed Sep 9 2015  Andrei Ismail <iandrei@gmail.com> 0.2
- Added support for automatic packaging on Ubuntu 14.04 and CentOS 7.
