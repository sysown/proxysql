# Don't try fancy stuff like debuginfo, which is useless on binary-only
# packages. Don't strip binary too
# Be sure buildpolicy set to do nothing
%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Summary: A high-performance MySQL proxy
Name: proxysql
Version: %{version}
Release: 1
License: GPL-3.0-only
Source: %{name}-%{version}.tar.gz
URL: https://www.proxysql.com/
Requires: gnutls
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
if [ ! -d /var/run/%{name} ]; then mkdir /var/run/%{name} ; fi
if [ ! -d /var/lib/%{name} ]; then mkdir /var/lib/%{name} ; fi
if ! id -u %{name} > /dev/null 2>&1; then useradd -r -U -s /bin/false -d /var/lib/%{name} -c "ProxySQL Server" %{name}; fi
chown -R %{name}: /var/lib/%{name} /var/run/%{name}
chown root:%{name} /etc/%{name}.cnf
chmod 640 /etc/%{name}.cnf
chkconfig --add %{name}

%preun
/etc/init.d/%{name} stop
chkconfig --del %{name}

%postun
rm -rf /var/run/%{name}

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/%{name}.cnf
%attr(640,root,%{name}) %{_sysconfdir}/%{name}.cnf
%config(noreplace) %attr(640,root,%{name}) %{_sysconfdir}/logrotate.d/%{name}
%{_bindir}/*
%{_sysconfdir}/init.d/%{name}
/usr/share/proxysql/tools/proxysql_galera_checker.sh
/usr/share/proxysql/tools/proxysql_galera_writer.pl

%changelog
