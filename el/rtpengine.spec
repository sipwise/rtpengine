Name:		ngcp-rtpengine
Version:	4.5.0
Release:	0%{?dist}
Summary:	The Sipwise NGCP rtpengine

Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/sipwise/rtpengine
Source0:	https://github.com/sipwise/rtpengine/archive/mr%{version}/%{name}-%{version}.tar.gz
Conflicts:	%{name}-kernel < %{version}-%{release}

BuildRequires:	gcc make pkgconfig redhat-rpm-config
BuildRequires:	glib2-devel libcurl-devel openssl-devel pcre-devel
BuildRequires:	xmlrpc-c-devel zlib-devel hiredis-devel
Requires:	nc
# Remain compat with other installations
Provides:	ngcp-rtpengine = %{version}-%{release}


%description
The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the Kamailio SIP proxy and forms a
drop-in replacement for any of the other available RTP and media proxies.


%package kernel
Summary:	NGCP rtpengine in-kernel packet forwarding
Group:		System Environment/Daemons
BuildRequires:	gcc make redhat-rpm-config iptables-devel
Requires:	iptables iptables-ipv6
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires: 	%{name}-dkms = %{version}-%{release}

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

%define binname rtpengine

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
install -D -p -m755 daemon/%{binname} %{buildroot}%{_sbindir}/%{binname}
# Install CLI (command line interface)
install -D -p -m755 utils/%{binname}-ctl %{buildroot}%{_sbindir}/%{binname}-ctl

## Install the init.d script and configuration file
install -D -p -m755 el/%{binname}.init \
	%{buildroot}%{_initrddir}/%{name}
install -D -p -m644 el/%{binname}.sysconfig \
	%{buildroot}%{_sysconfdir}/sysconfig/%{binname}
mkdir -p %{buildroot}%{_sharedstatedir}/%{name}

# Install the iptables plugin
install -D -p -m755 iptables-extension/libxt_RTPENGINE.so \
	%{buildroot}/%{_lib}/xtables/libxt_RTPENGINE.so

## DKMS module source install
install -D -p -m644 kernel-module/Makefile \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/Makefile
install -D -p -m644 kernel-module/xt_RTPENGINE.c \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.c
install -D -p -m644 kernel-module/xt_RTPENGINE.h \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.h
mkdir -p %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}
install -D -p -m644 kernel-module/rtpengine_config.h \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/rtpengine_config.h
install -D -p -m644 debian/dkms.conf.in %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf
sed -i -e "s/__VERSION__/%{version}-%{release}/g" %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf

# For RHEL 7, load the compiled kernel module on boot.
%if 0%{?rhel} == 7
  install -D -p -m644 kernel-module/xt_RTPENGINE.modules.load.d \
           %{buildroot}%{_sysconfdir}/modules-load.d/xt_RTPENGINE.conf
%endif

%pre
getent group %{name} >/dev/null || /usr/sbin/groupadd -r %{name}
getent passwd %{name} >/dev/null || /usr/sbin/useradd -r -g %{name} \
	-s /sbin/nologin -c "%{name} daemon" -d %{_sharedstatedir}/%{name} %{name}


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
%{_sbindir}/%{binname}
# CLI (command line interface)
%{_sbindir}/%{binname}-ctl

# init.d script and configuration file
%{_initrddir}/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}
%attr(0750,%{name},%{name}) %dir %{_sharedstatedir}/%{name}

# Documentation
%doc LICENSE README.md el/README.el.md debian/changelog debian/copyright


%files kernel
/%{_lib}/xtables/libxt_RTPENGINE.so


%files dkms
%{_usrsrc}/%{name}-%{version}-%{release}/
%if 0%{?rhel} == 7
  %{_sysconfdir}/modules-load.d/xt_RTPENGINE.conf
%endif


%changelog
* Thu Nov 24 2016 Marcel Weinberg <marcel@ng-voice.com>
  - Updated to ngcp-rtpengine version 4.5.0 and CentOS 7.2 
  - created a new variable "binname" to use rtpengine as name for the binaries
    (still using ngcp-rtpenginge as name of the package and daemon - aligned to the .deb packages)
  - fixed dependencies 
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

