Name:		ngcp-mediaproxy-ng
Version:	2.3.6
Release:	0%{?dist}
Summary:	The Sipwise NGCP mediaproxy-ng

Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/sipwise/mediaproxy-ng
Source0:	https://github.com/sipwise/mediaproxy-ng/archive/%{version}/%{name}-%{version}.tar.gz
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
# Install the userspace daemon
install -D -p -m755 daemon/mediaproxy-ng %{buildroot}/%{_sbindir}/mediaproxy-ng

## Install the init.d script and configuration file
install -D -p -m755 el/mediaproxy-ng.init \
	%{buildroot}/%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
install -D -p -m644 el/mediaproxy-ng.sysconfig \
	%{buildroot}/%{_sysconfdir}/sysconfig/mediaproxy-ng
mkdir -p %{buildroot}/%{_sharedstatedir}/mediaproxy-ng

# Install the iptables plugin
install -D -p -m755 iptables-extension/libxt_MEDIAPROXY.so \
	%{buildroot}/%{_lib}/xtables/libxt_MEDIAPROXY.so

## DKMS module source install
install -D -p -m644 kernel-module/Makefile \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/Makefile
install -D -p -m644 kernel-module/xt_MEDIAPROXY.c \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/xt_MEDIAPROXY.c
install -D -p -m644 kernel-module/xt_MEDIAPROXY.h \
	 %{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/xt_MEDIAPROXY.h
sed "s/__VERSION__/%{version}-%{release}/g" debian/dkms.conf.in > \
	%{buildroot}/%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r mediaproxy-ng 2> /dev/null || :
/usr/sbin/useradd -r -g mediaproxy-ng -s /sbin/nologin -c "mediaproxy-ng daemon" \
	-d %{_sharedstatedir}/mediaproxy-ng mediaproxy-ng \
	2> /dev/null || :


%post
if [ $1 -eq 1 ]; then
        /sbin/chkconfig --add %{name} || :
fi


%post dkms
# Add to DKMS registry, build, and install module
dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --force
true


%preun
if [ $1 = 0 ] ; then
        /sbin/service %{name} stop >/dev/null 2>&1
        /sbin/chkconfig --del %{name}
fi


%preun dkms
# Remove from DKMS registry
dkms remove -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --all
true


%files
# Userspace daemon
%{_sbindir}/mediaproxy-ng

# init.d script and configuration file
%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
%config(noreplace) %{_sysconfdir}/sysconfig/mediaproxy-ng
%dir %{_sharedstatedir}/mediaproxy-ng

# Documentation
%doc LICENSE README.md el/README.el.md debian/changelog debian/copyright


%files kernel
/%{_lib}/xtables/libxt_MEDIAPROXY.so


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
