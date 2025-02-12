Name:		ngcp-rtpengine
Version:	13.2.1.1+0~mr13.2.1.1
Release:	1%{?dist}
Summary:	The Sipwise NGCP rtpengine daemon
Group:		System Environment/Daemons
License:	GPLv3
URL:		https://github.com/sipwise/rtpengine
Source0:	https://github.com/sipwise/rtpengine/archive/%{name}-%{version}.tar.gz
Conflicts:	%{name}-kernel < %{version}-%{release}

%global with_transcoding 1
%{?_unitdir:%define has_systemd_dirs 1}

%if 0%{?openEuler} >= 1
%define redhat_rpm_config openEuler-rpm-config

%if 0%{?rhel} == 0

%if 0%{?openEuler} >= 2
%define rhel 9
%else
%define rhel 8
%endif

%endif
%else
%define redhat_rpm_config redhat-rpm-config
%endif

BuildRequires: gcc make pkgconfig %{redhat_rpm_config}
BuildRequires:	glib2-devel libcurl-devel openssl-devel pcre-devel
BuildRequires:	xmlrpc-c-devel zlib-devel hiredis-devel
BuildRequires:	libpcap-devel libevent-devel json-glib-devel
BuildRequires:	mosquitto-devel
BuildRequires:	gperf perl-IPC-Cmd
BuildRequires:	perl-podlators
BuildRequires:	libatomic
BuildRequires:	pkgconfig(libwebsockets)
BuildRequires:	pkgconfig(spandsp)
BuildRequires:	pkgconfig(opus)
%if 0%{?rhel} == 8
# LTS mr11.5.1 cannot build with gcc 8.5
BuildRequires: gcc-toolset-13
%endif
Requires(pre):	shadow-utils
%if 0%{?rhel} >= 8
BuildRequires:	pkgconfig(libmnl) pkgconfig(libnftnl) pandoc ncurses-devel
%endif
%if 0%{?rhel} >= 9
BuildRequires:	pkgconfig(libiptc)
%endif

%if 0%{?with_transcoding} > 0
BuildRequires:	ffmpeg-devel
Requires(pre):	ffmpeg-libs
%endif

Requires:	perl-Config-Tiny
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
BuildRequires:	gcc make %{redhat_rpm_config} iptables-devel
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	%{name}-dkms = %{version}-%{release}

%description kernel
%{summary}.


%package dkms
Summary:	Kernel module for NGCP rtpengine in-kernel packet forwarding
Group:		System Environment/Daemons
BuildArch:	noarch
BuildRequires:	%{redhat_rpm_config}
Requires:	gcc make
# Define requires according to the installed kernel.
%{?rhel:Requires: kernel-devel}
%{?fedora:Requires: kernel-devel}
%{?suse_version:Requires: kernel-source}
Requires(post):	dkms
Requires(preun): dkms

%description dkms
%{summary}.

%package utils
Summary:	Utilities and Perl modules for NGCP rtpengine
Requires:	perl-interpreter

%description utils
%{summary}.

%if 0%{?rhel} >= 8
%define mysql_devel_pkg mariadb-devel
%else
%define mysql_devel_pkg mysql-devel
%endif

%if 0%{?with_transcoding} > 0
%package recording
Summary:	The Sipwise NGCP rtpengine recording daemon
Group:		System Environment/Daemons
BuildRequires:	gcc make %{redhat_rpm_config} %{mysql_devel_pkg} ffmpeg-devel

%description recording
The Sipwise rtpengine media proxy has support for exporting media (RTP) packets
that it forwards. The rtpengine-recording daemon collects these exported packets
and decodes them into an audio format that can be listened to.

%endif

%define binname rtpengine


%prep
%setup -q -n %{name}-%{version}


%build
# we don't run configure, so consume the default
# build flags set by the distro
%{set_build_flags}
echo ==== CFLAGS = $CFLAGS ====
echo ==== CXXFLAGS = $CXXFLAGS ====
echo ==== LDFLAGS = $LDFLAGS ====

%if 0%{?rhel} == 8
# LTS mr11.5.1 cannot build with gcc 8.5
. /opt/rh/gcc-toolset-13/enable
%endif
%if 0%{?with_transcoding} > 0
RTPENGINE_VERSION="\"%{version}-%{release}\"" make all
%else
RTPENGINE_VERSION="\"%{version}-%{release}\"" make with_transcoding=no all
%endif

%install
# we don't run configure, so consume the default
# build flags set by the distro
%{set_build_flags}
echo ---- CFLAGS = $CFLAGS ----
echo ---- CXXFLAGS = $CXXFLAGS ----
echo ---- LDFLAGS = $LDFLAGS ----
# Install the userspace daemon
%if 0%{?with_transcoding} > 0
RTPENGINE_VERSION="\"%{version}-%{release}\"" make DESTDIR=%{buildroot} install
%else
RTPENGINE_VERSION="\"%{version}-%{release}\"" make DESTDIR=%{buildroot} with_transcoding=no install
%endif

## Install the init.d script and configuration file
%if 0%{?has_systemd_dirs}
install -D -p -m644 el/%{binname}.service \
	%{buildroot}%{_unitdir}/%{binname}.service
%else
install -D -p -m755 el/%{binname}.init \
	%{buildroot}%{_initrddir}/%{name}
%endif
%if 0%{?with_transcoding} > 0
%if 0%{?has_systemd_dirs}
install -D -p -m644 el/%{binname}-recording.service \
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
mkdir -p %{buildroot}%{_var}/lib/%{binname}-recording
mkdir -p %{buildroot}%{_var}/spool/%{binname}

# Install config files
install -D -p -m644 etc/%{binname}.conf \
	%{buildroot}%{_sysconfdir}/%{binname}/%{binname}.conf
%if 0%{?with_transcoding} > 0
install -D -p -m644 etc/%{binname}-recording.conf \
	%{buildroot}%{_sysconfdir}/%{binname}/%{binname}-recording.conf
%endif

## DKMS module source install
install -D -p -m644 kernel-module/Makefile \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/Makefile
install -D -p -m644 kernel-module/xt_RTPENGINE.c \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.c
install -D -p -m644 kernel-module/xt_RTPENGINE.h \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/xt_RTPENGINE.h
install -D -p -m644 kernel-module/common_stats.h \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/common_stats.h
install -D -p -m644 kernel-module/*.inc \
	 %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/
install -D -p -m644 debian/ngcp-rtpengine-kernel-dkms.dkms %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf
sed -i -e "s/#MODULE_VERSION#/%{version}-%{release}/g" %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf
%if 0%{?with_transcoding} > 0
install -m755 -d %{buildroot}%{_datarootdir}/%{binname}-perftest
install -m444 fixtures/* %{buildroot}%{_datarootdir}/%{binname}-perftest
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
%{_bindir}/%{binname}
# CLI (command line interface)
%{_bindir}/%{binname}-ctl
# CLI table helper
# init.d script and configuration file
%if 0%{?has_systemd_dirs}
%{_unitdir}/%{binname}.service
%else
%{_initrddir}/%{name}
%endif
%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}
# default config
%config(noreplace) %{_sysconfdir}/%{binname}/%{binname}.conf
# spool directory
%attr(0750,%{name},%{name}) %dir %{_var}/spool/%{binname}
# Documentation
%doc LICENSE README.md debian/changelog debian/copyright
%{_mandir}/man8/%{binname}.8*

%files kernel

%files dkms
%{_usrsrc}/%{name}-%{version}-%{release}/


%files utils
%{_bindir}/%{binname}-ctl
%{_bindir}/%{binname}-ng-client
%{_libexecdir}/%{binname}/%{binname}-get-table
%{_mandir}/man1/%{binname}-ctl.1*
%{_mandir}/man1/%{binname}-ng-client.1.*
%if 0%{?with_transcoding} > 0
%{_bindir}/%{binname}-perftest
%{_datarootdir}/%{binname}-perftest/*
%endif

%if 0%{?with_transcoding} > 0
%files recording
# Recording daemon
%{_bindir}/%{binname}-recording
# Init script
%if 0%{?has_systemd_dirs}
%{_unitdir}/%{binname}-recording.service
%else
%{_initrddir}/%{name}-recording
%endif
# Sysconfig
%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}-recording
# Default config
%config(noreplace) %{_sysconfdir}/%{binname}/%{binname}-recording.conf
# recording directory
%attr(0750,%{name},%{name}) %dir %{_sharedstatedir}/%{binname}-recording
%{_mandir}/man8/%{binname}-recording.8*
%endif

%changelog
* Thu Nov 11 2021 Anton Voylenko <anton.voylenko@novait.com.ua>
  - update packages metadata
  - remove the "archname" variable
  - do not override service configuration
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
