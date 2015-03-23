Name:		ngcp-rtpengine
Version:	2.3.6
Release:	0%{?dist}
Summary:	The Sipwise NGCP rtpengine

Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/sipwise/rtpengine
Source0:	https://github.com/sipwise/rtpengine/archive/%{version}/%{name}-%{version}.tar.gz
Conflicts:	%{name}-kernel < %{version}

BuildRequires:	gcc make pkgconfig redhat-rpm-config
BuildRequires:	glib2-devel libcurl-devel openssl-devel pcre-devel
BuildRequires:	xmlrpc-c-devel zlib-devel
Requires:	nc


%description
The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the Kamailio SIP proxy and forms a
drop-in replacement for any of the other available RTP and media proxies.


%package kernel
Summary:	NGCP rtpengine in-kernel packet forwarding
Group:		System Environment/Daemons
BuildRequires:	gcc make redhat-rpm-config iptables-devel
Requires:	iptables iptables-ipv6 ngcp-rtpengine = %{version}
Requires:	ngcp-rtpengine-dkms = %{version}

%description kernel
%{summary}.


%package dkms
Summary:	Kernel module for NGCP rtpengine in-kernel packet forwarding
Group:		System Environment/Daemons
BuildArch:	noarch
BuildRequires:	redhat-rpm-config
Requires:	gcc make
Requires(post):	epel-release dkms
Requires(preun): epel-release dkms

%description dkms
%{summary}.


%prep
%setup -q


%build
cd daemon
RTPENGINE_VERSION="\"%{version}-%{release}\"" make
cd ../iptables-extension
RTPENGINE_VERSION="\"%{version}-%{release}\"" make
cd ..


%install
# Install the userspace daemon
install -D -p -m755 daemon/rtpengine %{buildroot}/%{_sbindir}/rtpengine
# Install CLI (command line interface)
install -D -p -m755 utils/rtpengine-ctl %{buildroot}/%{_sbindir}/rtpengine-ctl

## Install the init.d script and configuration file
install -D -p -m755 el/rtpengine.init \
	%{buildroot}/%{_sysconfdir}/rc.d/init.d/rtpengine
install -D -p -m644 el/rtpengine.sysconfig \
	%{buildroot}/%{_sysconfdir}/sysconfig/rtpengine
mkdir -p %{buildroot}/%{_sharedstatedir}/rtpengine

# Install the iptables plugin
install -D -p -m755 iptables-extension/libxt_RTPENGINE.so \
	%{buildroot}/%{_lib}/xtables/libxt_RTPENGINE.so

## DKMS module source install
install -D -p -m644 kernel-module/Makefile \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/Makefile
install -D -p -m644 kernel-module/xt_RTPENGINE.c \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.c
install -D -p -m644 kernel-module/xt_RTPENGINE.h \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.h
sed "s/__VERSION__/%{version}-%{release}/g" debian/dkms.conf.in > \
	%{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r rtpengine 2> /dev/null || :
/usr/sbin/useradd -r -g rtpengine -s /sbin/nologin -c "rtpengine daemon" \
	-d %{_sharedstatedir}/rtpengine rtpengine \
	2> /dev/null || :


%post
if [ $1 -eq 1 ]; then
        /sbin/chkconfig --add rtpengine || :
fi


%post dkms
# Add to DKMS registry, build, and install module
dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --force
true


%preun
if [ $1 = 0 ] ; then
        /sbin/service rtpengine stop >/dev/null 2>&1
        /sbin/chkconfig --del rtpengine
fi


%preun dkms
# Remove from DKMS registry
dkms remove -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --all
true


%files
# Userspace daemon
%{_sbindir}/rtpengine
# CLI (command line interface)
%{_sbindir}/rtpengine-ctl

# init.d script and configuration file
%{_sysconfdir}/rc.d/init.d/rtpengine
%config(noreplace) %{_sysconfdir}/sysconfig/rtpengine
%dir %{_sharedstatedir}/rtpengine

# Documentation
%doc LICENSE README.md el/README.el.md debian/changelog debian/copyright


%files kernel
/%{_lib}/xtables/libxt_RTPENGINE.so


%files dkms
%attr(0755,root,root) %{_usrsrc}/%{name}-%{version}-%{release}/


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
