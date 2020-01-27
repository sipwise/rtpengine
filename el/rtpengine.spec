Name:		ngcp-rtpengine
Version:	8.3.0.0+0~mr8.3.0.0
Release:	1%{?dist}
Summary:	The Sipwise NGCP rtpengine

Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/sipwise/rtpengine
Source0:	https://github.com/sipwise/rtpengine/archive/mr%{version}/%{name}-%{version}.tar.gz
Conflicts:	%{name}-kernel < %{version}-%{release}

%global with_transcoding 1
%{?_unitdir:%define has_systemd_dirs 1}

BuildRequires:	gcc make pkgconfig redhat-rpm-config
BuildRequires:	glib2-devel libcurl-devel openssl-devel pcre-devel
BuildRequires:	xmlrpc-c-devel zlib-devel hiredis-devel
BuildRequires:	libpcap-devel libevent-devel json-glib-devel 
BuildRequires:	gperf perl-IPC-Cmd
BuildRequires:  spandsp-devel
Requires(pre):	shadow-utils

%if 0%{?with_transcoding} > 0
BuildRequires:  ffmpeg-devel
Requires(pre):	ffmpeg-libs
%endif

Requires:	nc
# Remain compat with other installations
Provides:	ngcp-rtpengine = %{version}-%{release}

%description
The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the Kamailio SIP proxy and forms a
drop-in replacement for any of the other available RTP and media proxies.

%if 0%{?rhel} < 7
%define iptables_ipv6 1
%endif
%package kernel
Summary:	NGCP rtpengine in-kernel packet forwarding
Group:		System Environment/Daemons
BuildRequires:	gcc make redhat-rpm-config iptables-devel
Requires:	iptables %{?iptables_ipv6:iptables-ipv6}
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
# Define requires according to the installed kernel.
%{?rhel:Requires: kernel-devel}
%{?fedora:Requires: kernel-devel}
%{?suse_version:Requires: kernel-source}
Requires(post):	dkms
Requires(preun): dkms

%description dkms
%{summary}.

%if 0%{?rhel} >= 8
%define mysql_devel_pkg mariadb-devel
%else
%define mysql_devel_pkg mysql-devel
%endif

%if 0%{?with_transcoding} > 0
%package recording
Summary:        NGCP rtpengine recording daemon packet
Group:          System Environment/Daemons
BuildRequires:  gcc make redhat-rpm-config %{mysql_devel_pkg} ffmpeg-devel

%description recording
%{summary}.

%endif

%define binname rtpengine
%define archname rtpengine-mr


%prep
%setup -q -n %{archname}%{version}


%build
%if 0%{?with_transcoding} > 0
cd daemon
RTPENGINE_VERSION="\"%{version}-%{release}\"" make
cd ../iptables-extension
RTPENGINE_VERSION="\"%{version}-%{release}\"" make
cd ../recording-daemon
RTPENGINE_VERSION="\"%{version}-%{release}\"" make
cd ..
%else
cd daemon
RTPENGINE_VERSION="\"%{version}-%{release}\"" make with_transcoding=no
cd ../iptables-extension
RTPENGINE_VERSION="\"%{version}-%{release}\"" make with_transcoding=no
cd ..
%endif

%install
# Install the userspace daemon
install -D -p -m755 daemon/%{binname} %{buildroot}%{_sbindir}/%{binname}
# Install CLI (command line interface)
install -D -p -m755 utils/%{binname}-ctl %{buildroot}%{_sbindir}/%{binname}-ctl
# Install recording daemon
%if 0%{?with_transcoding} > 0
install -D -p -m755 recording-daemon/%{binname}-recording %{buildroot}%{_sbindir}/%{binname}-recording
%endif

## Install the init.d script and configuration file
%if 0%{?has_systemd_dirs}
install -D -p -m755 el/%{binname}.service \
	%{buildroot}%{_unitdir}/%{binname}.service
%else
install -D -p -m755 el/%{binname}.init \
	%{buildroot}%{_initrddir}/%{name}
%endif
%if 0%{?with_transcoding} > 0
%if 0%{?has_systemd_dirs}
install -D -p -m755 el/%{binname}-recording.service \
	%{buildroot}%{_unitdir}/%{binname}-recording.service
%else
install -D -p -m755 el/%{binname}-recording.init \
        %{buildroot}%{_initrddir}/%{name}-recording
%endif
%endif
install -D -p -m644 el/%{binname}.sysconfig \
	%{buildroot}%{_sysconfdir}/sysconfig/%{binname}
%if 0%{?with_transcoding} > 0
install -D -p -m644 el/%{binname}-recording.sysconfig \
	%{buildroot}%{_sysconfdir}/sysconfig/%{binname}-recording
%endif
mkdir -p %{buildroot}%{_sharedstatedir}/%{name}
mkdir -p %{buildroot}%{_var}/spool/%{binname}

# Install config files
install -D -p -m644 etc/%{binname}.sample.conf \
	%{buildroot}%{_sysconfdir}/%{binname}/%{binname}.conf
%if 0%{?with_transcoding} > 0
install -D -p -m644 etc/%{binname}-recording.sample.conf \
	%{buildroot}%{_sysconfdir}/%{binname}/%{binname}-recording.conf
%endif

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
%if 0%{?has_systemd_dirs}
        systemctl daemon-reload
%else
        /sbin/chkconfig --add %{name} || :
%endif
fi


%post dkms
# Add to DKMS registry, build, and install module
# The kernel version can be overridden with "--define kversion foo" on rpmbuild,
# e.g. --define "kversion 2.6.32-696.23.1.el6.x86_64"
%{!?kversion: %define kversion %{nil}}

%if "%{kversion}" != ""
  dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
  dkms build -m %{name} -v %{version}-%{release} -k %{kversion} --rpm_safe_upgrade &&
  dkms install -m %{name} -v %{version}-%{release} -k %{kversion} --rpm_safe_upgrade --force
%else
  dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
  dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
  dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --force
%endif
true


%preun
if [ $1 = 0 ] ; then
%if 0%{?has_systemd_dirs}
        systemctl stop %{binname}.service
        systemctl disable %{binname}.service

%else
        /sbin/service %{name} stop >/dev/null 2>&1
        /sbin/chkconfig --del %{name}
%endif
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
%if 0%{?has_systemd_dirs}
%{_unitdir}/%{binname}.service
%else
%{_initrddir}/%{name}
%endif
%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}
%attr(0750,%{name},%{name}) %dir %{_sharedstatedir}/%{name}
# default config
%{_sysconfdir}/%{binname}/%{binname}.conf
# Documentation
%doc LICENSE README.md el/README.el.md debian/changelog debian/copyright


%files kernel
/%{_lib}/xtables/libxt_RTPENGINE.so


%files dkms
%{_usrsrc}/%{name}-%{version}-%{release}/
%if 0%{?rhel} == 7
  %{_sysconfdir}/modules-load.d/xt_RTPENGINE.conf
%endif


%if 0%{?with_transcoding} > 0
%files recording
# Recording daemon
%{_sbindir}/%{binname}-recording
# Init script
%if 0%{?has_systemd_dirs}
%{_unitdir}/%{binname}-recording.service
%else
%{_initrddir}/%{name}-recording
%endif
# Sysconfig
%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}-recording
# Default config
%{_sysconfdir}/%{binname}/%{binname}-recording.conf
# spool directory
%attr(0750,%{name},%{name}) %dir %{_var}/spool/%{binname}
%endif

%changelog
* Tue Jul 10 2018 netaskd <netaskd@gmail.com> - 6.4.0.0-1
  - update to ngcp-rtpengine version 6.4.0.0
  - add packet recording
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

