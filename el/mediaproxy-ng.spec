Name:		ngcp-mediaproxy-ng
Version:	2.3.2
Release:	0%{?dist}
Summary:	The Sipwise NGCP mediaproxy-ng

Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/crocodilertc/mediaproxy-ng
Source:		%{name}-%{version}.tar.gz
Conflicts:	%{name}-kernel < %{version}
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	gcc make pkgconfig redhat-rpm-config
BuildRequires:	glib2-devel libcurl-devel openssl-devel pcre-devel
BuildRequires:	xmlrpc-c-devel zlib-devel
Requires:	glibc libcurl openssl pcre xmlrpc-c


%description
The Sipwise NGCP mediaproxy-ng is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the Kamailio SIP proxy and forms a
drop-in replacement for any of the other available RTP and media proxies.


%package kernel
Summary:	NGCP mediaproxy-ng in-kernel packet forwarding
Group:		System Environment/Daemons
BuildRequires:	gcc make redhat-rpm-config iptables-devel
Requires:	iptables iptables-ipv6 ngcp-mediaproxy-ng = %{version}
Requires:	ngcp-mediaproxy-ng-dkms = %{version}

%description kernel
NGCP mediaproxy-ng in-kernel packet forwarding


%package dkms
Summary:	Kernel module for NGCP mediaproxy-ng in-kernel packet forwarding
Group:		System Environment/Daemons
BuildArch:	noarch
BuildRequires:	redhat-rpm-config
Requires:	gcc make
Requires(post):	epel-release dkms
Requires(preun): epel-release dkms

%description dkms
Kernel module for mediaproxy-ng in-kernel packet forwarding


%prep
%setup -q


%build
cd daemon
MEDIAPROXY_VERSION="\"%{version}-%{release}\"" make
cd ../iptables-extension
MEDIAPROXY_VERSION="\"%{version}-%{release}\"" make
cd ..


%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"

# Install the userspace daemon
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
install -m755 daemon/mediaproxy-ng $RPM_BUILD_ROOT/%{_sbindir}/mediaproxy-ng

## Install the init.d script and configuration file
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d
install -m755 el/mediaproxy-ng.init \
	$RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
install -m644 el/mediaproxy-ng.sysconfig \
	$RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/mediaproxy-ng
mkdir -p $RPM_BUILD_ROOT/%{_sharedstatedir}/mediaproxy-ng

# Install the iptables plugin
mkdir -p $RPM_BUILD_ROOT/%{_lib}/xtables
install -m755 iptables-extension/libxt_MEDIAPROXY.so \
	$RPM_BUILD_ROOT/%{_lib}/xtables/libxt_MEDIAPROXY.so

# Install the documentation
mkdir -p $RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version}-%{release}
install -m644 README.md \
	$RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version}-%{release}/README.md
install -m644 debian/changelog \
	$RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version}-%{release}/changelog
install -m644 debian/copyright \
	$RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version}-%{release}/copyright
install -m644 el/README.md \
	$RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version}-%{release}/README.el.md

## DKMS module source install
mkdir -p $RPM_BUILD_ROOT/%{_usrsrc}/%{name}-%{version}-%{release}
install -m644 kernel-module/Makefile \
	 $RPM_BUILD_ROOT/%{_usrsrc}/%{name}-%{version}-%{release}/Makefile
install -m644 kernel-module/xt_MEDIAPROXY.c \
	 $RPM_BUILD_ROOT/%{_usrsrc}/%{name}-%{version}-%{release}/xt_MEDIAPROXY.c
install -m644 kernel-module/xt_MEDIAPROXY.h \
	 $RPM_BUILD_ROOT/%{_usrsrc}/%{name}-%{version}-%{release}/xt_MEDIAPROXY.h
sed "s/__VERSION__/%{version}-%{release}/g" debian/dkms.conf.in > \
	$RPM_BUILD_ROOT/%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r mediaproxy-ng 2> /dev/null || :
/usr/sbin/usradd -r -g mediaproxy-ng -s /bin/false -c "mediaproxy-ng daemon" \
	-d %{_docdir}/%{name}-%{version}-%{release} mediaproxy-ng \
	2> /dev/null || :


%post
/sbin/chkconfig --add mediaproxy-ng


%post dkms
# Add to DKMS registry, build, and install module
dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --force
true


%preun
/sbin/service mediaproxy-ng stop
/sbin/chkconfig --del mediaproxy-ng


%preun dkms
# Remove from DKMS registry
dkms remove -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --all
true


%files
%defattr(-,root,root,-)
# Userspace daemon
%{_sbindir}/mediaproxy-ng

# init.d script and configuration file
%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
%config(noreplace) %{_sysconfdir}/sysconfig/mediaproxy-ng
%dir %{_sharedstatedir}/mediaproxy-ng

# Documentation
%dir %{_docdir}/%{name}-%{version}-%{release}
%doc %{_docdir}/%{name}-%{version}-%{release}/README.md
%doc %{_docdir}/%{name}-%{version}-%{release}/changelog
%doc %{_docdir}/%{name}-%{version}-%{release}/copyright
%doc %{_docdir}/%{name}-%{version}-%{release}/README.el.md


%files kernel
%defattr(-,root,root,-)
/%{_lib}/xtables/libxt_MEDIAPROXY.so


%files dkms
%defattr(-,root,root,0755)
%{_usrsrc}/%{name}-%{version}-%{release}/


%changelog
* Mon Nov 11 2013 Peter Dunkley <peter.dunkley@crocodilertc.net>
  - Updated version to 2.3.2
  - Set license to GPLv3
* Thu Aug 15 2013 Peter Dunkley <peter.dunkley@crocodilertc.net>
  - init.d scripts and configuration file
* Wed Aug 14 2013 Peter Dunkley <peter.dunkley@crocodilertc.net>
  - First version of .spec file
  - Builds and installs userspace daemon (but no init.d scripts etc yet)
  - Builds and installs the iptables plugin
  - DKMS package for the kernel module
