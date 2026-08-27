# we don't want separate debuginfo packages
%global        _enable_debug_package 0
%define        debug_package %{nil}
# do not strip binaries
%global        __strip /bin/true
%define        __spec_install_post %{nil}
%define        __os_install_post %{_dbpath}/brp-compress %{nil}

Summary: A high-performance MySQL and PostgreSQL proxy
Name: proxysql
Version: %{version}
Release: 1
License: GPL-3.0-only
Source: %{name}-%{version}.tar.gz
URL: https://proxysql.com/
Requires: gnutls
Requires: (openssl >= 3.0.0 or openssl3 >= 3.0.0)
#BuildRequires: systemd-rpm-macros
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Provides: user(%{name})
Provides: group(%{name})

%description
%{summary}

%prep
%setup -q

%pre
# setup user, group
getent passwd %{name} &>/dev/null || useradd -r -U -s /bin/false -d /var/lib/%{name} -c "ProxySQL Server" %{name}

%build
# Packages are pre-built, nothing to do

%install
export DONT_STRIP=1
# Clean buildroot and install files
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}
mkdir -p %{buildroot}/var/run/%{name}
mkdir -p %{buildroot}/var/lib/%{name}
# proxysql-cli is the same binary under a second name; main() dispatches on
# argv[0] (see src/main.cpp) and never starts the daemon in that mode. Shipped
# as a real symlink so rpm owns it and removes it on uninstall; the existing
# %{_bindir}/* glob in %files already picks it up.
ln -sf proxysql %{buildroot}%{_bindir}/proxysql-cli

%clean
rm -rf %{buildroot}

%post
# install service
%systemd_post %{name}.service
#%systemd_post_with_reload %{name}.service

%preun
# remove service
%systemd_preun %{name}.service

%postun
# remove user, group on uninstall
# dont, its against the recommended practice
#if [ "$1" == "0" ]; then
#	groupdel %{name}
#	userdel %{name}
#fi

%posttrans
# reload, restart service
#%systemd_posttrans_with_reload %{name}.service
#%systemd_posttrans_with_restart %{name}.service

%files
%defattr(-,root,root,-)
%config(noreplace) %attr(640,root,%{name}) %{_sysconfdir}/%{name}.cnf
%config(noreplace) %attr(640,root,%{name}) %{_sysconfdir}/logrotate.d/%{name}
%{_bindir}/*
%{_sysconfdir}/systemd/system/%{name}.service
%{_sysconfdir}/systemd/system/%{name}-initial.service
/usr/share/proxysql/tools/proxysql_galera_checker.sh
/usr/share/proxysql/tools/proxysql_galera_writer.pl
# Plugin .so artefacts for v4.0+ chassis builds (mysqlx, genai/MCP).
# See rhel-compliant proxysql.spec for the rationale on the gate.
%if 0%{?with_plugins}
%dir /usr/lib/proxysql
/usr/lib/proxysql/*.so
%endif
%config(noreplace) %attr(750,%{name},%{name}) /var/run/%{name}/
%config(noreplace) %attr(750,%{name},%{name}) /var/lib/%{name}/

%changelog
