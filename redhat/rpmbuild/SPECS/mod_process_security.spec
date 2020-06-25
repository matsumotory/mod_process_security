%{!?_httpd_mmn:        %{expand: %%global _httpd_mmn %%(cat %{_includedir}/httpd/.mmn || echo 0-0)}}
%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:     %{expand: %%global _httpd_moddir %%{_libdir}/httpd/modules}}

Summary: A suEXEC module for CGI and DSO for Apache 2
Name: mod_process_security
Version: 1.2.0
Release: 1%{?dist}
License: MIT
Group: System Environment/Daemons
URL: https://github.com/matsumotory/mod_process_security
Source0: https://github.com/matsumotory/%{name}/archive/v%{version}.tar.gz
Source1: mod_process_security.conf
BuildRequires: httpd-devel
BuildRequires: pkgconfig
BuildRequires: libcap-devel
Requires: httpd-mmn = %{_httpd_mmn}

%description
This Apache module is a suEXEC module for CGI and DSO.
Improvement of mod_ruid2(vulnerability) and mod_suexec(performance).

%prep
%setup -q

%build
make

%install
rm -rf %{buildroot}
install -D -p -m 0755 .libs/mod_process_security.so \
    %{buildroot}%{_httpd_moddir}/mod_process_security.so

install -D -p -m 0644 %{SOURCE1} \
    %{buildroot}%{_httpd_confdir}/mod_process_security.conf

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%config(noreplace) %{_httpd_confdir}/mod_process_security.conf
%{_httpd_moddir}/mod_process_security.so

%changelog
* Thu Jun 25 2020 Jun Futagawa <jfut@integ.jp> - 1.2.0-1
- Update to version 1.2.0

* Thu Nov 28 2019 Jun Futagawa <jfut@integ.jp> - 1.1.4-2
- Base on commit: 31a0c70e9d6d6a6160525eefab6c93d8815365b4 (included WebDAV support)
- Improve default mod_process_security.conf
- Add support for CentOS 8, but not support WebDAV on CentOS 8

* Thu Nov 28 2019 Jun Futagawa <jfut@integ.jp> - 1.1.4-1
- Initial release
