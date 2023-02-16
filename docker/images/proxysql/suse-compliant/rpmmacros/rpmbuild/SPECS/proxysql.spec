%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Summary: A high-performance MySQL proxy
Name: proxysql
Version: %{version}
Release: 1
License: GPL+
Group: Development/Tools
SOURCE0 : %{name}-%{version}.tar.gz
URL: https://proxysql.com/
Requires: gnutls
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%pre
# Cleanup artifacts
if [ -f /var/lib/%{name}/PROXYSQL_UPGRADE ]; then
    rm -fr /var/lib/%{name}/PROXYSQL_UPGRADE
fi

%build
# Packages are pre-built, nothing to do

%install
# Clean buildroot and install files
/bin/rm -rf %{buildroot}
/bin/mkdir -p %{buildroot}
/bin/cp -a * %{buildroot}

%clean
/bin/rm -rf %{buildroot}

%post
# Create relevant user, directories and configuration files
if [ ! -d /var/run/%{name} ]; then /bin/mkdir /var/run/%{name} ; fi
if [ ! -d /var/lib/%{name} ]; then /bin/mkdir /var/lib/%{name} ; fi
if ! id -u %{name} > /dev/null 2>&1; then useradd -r -U -s /bin/false -d /var/lib/%{name} -c "ProxySQL Server" %{name}; fi
/bin/chown -R %{name}: /var/lib/%{name} /var/run/%{name}
/bin/chown root:%{name} /etc/%{name}.cnf
/bin/chmod 640 /etc/%{name}.cnf
# Configure systemd appropriately.
/bin/systemctl daemon-reload
/bin/systemctl enable %{name}.service
# Notify that a package update is in progress in order to start service.
if [ $1 -eq 2 ]; then /bin/touch /var/lib/%{name}/PROXYSQL_UPGRADE ; fi

%preun
# When uninstalling always try stop the service, ignore failures
/bin/systemctl stop %{name} || true

%postun
if [ $1 -eq 0 ]; then
    # This is a pure uninstall, systemd unit file removed
    # only daemon-reload is needed.
    /bin/systemctl daemon-reload
else
    # This is an upgrade, ProxySQL should be started. This
    # logic works for packages newer than 2.0.7 and ensures
    # a faster restart time.
    /bin/systemctl start %{name}.service
    /bin/rm -fr /var/lib/%{name}/PROXYSQL_UPGRADE
fi

%posttrans
if [ -f /var/lib/%{name}/PROXYSQL_UPGRADE ]; then
    # This is a safeguard to start the service after an update
    # which supports legacy "preun" / "postun" logic and will
    # only execute for packages before 2.0.7.
    /bin/systemctl start %{name}.service
    /bin/rm -fr /var/lib/%{name}/PROXYSQL_UPGRADE
fi

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/%{name}.cnf
%attr(640,root,%{name}) %{_sysconfdir}/%{name}.cnf
%config(noreplace) %attr(640,root,%{name}) %{_sysconfdir}/logrotate.d/%{name}
%{_bindir}/*
%{_sysconfdir}/systemd/system/%{name}.service
%{_sysconfdir}/systemd/system/%{name}-initial.service
/usr/share/proxysql/tools/proxysql_galera_checker.sh
/usr/share/proxysql/tools/proxysql_galera_writer.pl

%changelog
