# %%global _gitrev a4cca5f
# _gitrev define is used only if patching to build with commits from master that are not in a release.
# To use _gitrev and patching, uncomment top line by removing the "#" and one of the 2 percent signs.

# If using a patchfile to apply updates to a release, set _gitrev to the hash of the commit,
# and create a patchfile with updates from the last release:
# From the rtpengine git repository with the master branch checked out:
# git diff --patch --stat mr7.2.1.4 > ~/rpmbuild/SOURCES/rtpengine-7.2.1.4-2.gita4cca5f.patch

Summary: Sipwise NGCP RTP media proxy
Name: rtpengine
Version: 7.3.1.1
Release: 0%{?_gitrev:.git%{_gitrev}}%{?dist}
License: GPLv3
URL: https://github.com/sipwise/rtpengine

%undefine _disable_source_fetch
Source0: https://github.com/sipwise/rtpengine/archive/mr%{version}.tar.gz
Source1: %{name}.service
Source2: %{name}-recording.service
Source3: %{name}.tmpfilesd
Source4: %{name}-rtp.xml

# if _gitrev is defined at the top, apply the patch file to bring the release tarfile up to date
%if 0%{?_gitrev:1}
Patch0: %{name}-%{version}-%{release}.patch
%endif

BuildRequires: bcg729-devel
BuildRequires: ffmpeg-devel
BuildRequires: gcc
BuildRequires: glib2-devel
BuildRequires: gperf
BuildRequires: hiredis-devel
BuildRequires: iptables-devel
BuildRequires: json-glib-devel
BuildRequires: libcurl-devel
BuildRequires: libevent-devel
BuildRequires: libpcap-devel
BuildRequires: openssl-devel
BuildRequires: pcre-devel
BuildRequires: perl-generators
BuildRequires: perl-IPC-Cmd
BuildRequires: perl-podlators
BuildRequires: pkgconfig
BuildRequires: systemd-devel
BuildRequires: xmlrpc-c-devel
BuildRequires: zlib-devel

Requires(pre): shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

Requires: openssl


%description
The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based media
traffic. It's meant to be used with the Kamailio SIP proxy and forms a drop-in
replacement for any of the other available RTP and media proxies. When used in
combination with the %{name}-dkms package, support for in-kernel packet
forwarding is enabled.


%package firewalld
Summary: Sipwise NGCP RTP media proxy firewalld support
BuildArch: noarch
Requires: firewalld

%description firewalld
firewalld support for the Sipwise NGCP RTP media proxy


%package kernel
Summary: Sipwise NGCP RTP media proxy kernel support
Requires(pre): coreutils
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: iptables
Provides: %{name}-kmod-common = %{version}

%description kernel
Kernel support for the Sipwise NGCP RTP media proxy


%package recording-daemon
Summary: Sipwise NGCP RTP media recording daemon
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: mariadb-devel

%description recording-daemon
FFmpeg-based media recording daemon for the Sipwise NGCP RTP media proxy

%package dkms
Summary:        Kernel module for NGCP rtpengine in-kernel packet forwarding
Group:          System Environment/Daemons
BuildArch:      noarch
BuildRequires:  redhat-rpm-config
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       gcc make
Requires(post): dkms
Requires(preun): dkms

%description dkms
%{summary}.


%prep
%autosetup -n %{name}-mr%{version} -p1

# source file edits

# set recording daemon wav file output for 2 channels, 16-bits
sed -i '/stereo mixing goes here.*/a \\tout_format.channels = 2;\n\tout_format.format = AV_SAMPLE_FMT_S16;'  recording-daemon/decoder.c
# set output wav file for mu-law codec
# sed -i 's/str_init(&codec, "PCM-S16LE");/str_init(&codec, "PCM-MULAW");/' recording-daemon/output.c

# set mixer to join channels to stereo output instead of mixing together
sed -i 's/define NUM_INPUTS 4/define NUM_INPUTS 2/' recording-daemon/mix.c
sed -i 's/no amix filter available/no amerge filter available/' recording-daemon/mix.c
sed -i 's/avfilter_get_by_name("amix");/avfilter_get_by_name("amerge");/' recording-daemon/mix.c

# create small source files for CentOS here which are not in sipwise rtpengine repo
cat <<EOF > %{_sourcedir}/%{name}.service
[Unit]
Description=Sipwise NGCP rtpengine RTP proxy
Documentation=https://github.com/sipwise/rtpengine
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=rtpengine
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE
ExecStart=/usr/sbin/rtpengine -f --config-file=/etc/rtpengine/rtpengine.conf --config-section=rtpengine --pidfile=/run/rtpengine/rtpengine.pid
PIDFile=/run/rtpengine/rtpengine.pid
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > %{_sourcedir}/%{name}-recording.service
[Unit]
Description=Sipwise NGCP rtpengine RTP recording daemon
Documentation=https://github.com/sipwise/rtpengine
After=rtpengine.service
Requires=rtpengine.service

[Service]
Type=notify
User=rtpengine
ExecStart=/usr/sbin/rtpengine-recording -f --config-file=/etc/rtpengine/rtpengine.conf --config-section=rtpengine-recording --pidfile=/run/rtpengine/rtpengine-recording.pid
PIDFile=/run/rtpengine/rtpengine-recording.pid
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > %{_sourcedir}/%{name}.tmpfilesd
d /run/rtpengine 0750 rtpengine rtpengine
EOF

cat <<EOF > %{_sourcedir}/%{name}-rtp.xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>RTPEngine - RTP</short>
  <description>Sipwise NGCP RTP media proxy - RTP transport</description>
  <port port="30000-40000" protocol="udp"/>
</service>
0EOF

%build
export RTPENGINE_VERSION=%{version}-%{release}

%make_build -C daemon
%make_build -C iptables-extension
%make_build -C recording-daemon

%install
# Install configuration
mkdir -p %{buildroot}%{_sysconfdir}/%{name}
install -D -m 0644 etc/%{name}.sample.conf %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf

# Install systemd service, and systemd-tmpfilesd files
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_tmpfilesdir}
install -D -m 0644 %{S:1} %{buildroot}%{_unitdir}/%{name}.service
install -D -m 0644 %{S:2} %{buildroot}%{_unitdir}/%{name}-recording.service
install -D -m 0644 %{S:3} %{buildroot}%{_tmpfilesdir}/%{name}.conf

# Install binary and iptables module
install -D -p -m 0755 daemon/%{name} %{buildroot}%{_sbindir}/%{name}
install -D -p -m 0755 iptables-extension/libxt_RTPENGINE.so %{buildroot}%{_libdir}/xtables/libxt_RTPENGINE.so

# Install firewalld service
mkdir -p -m 0750 %{buildroot}%{_prefix}/lib/firewalld/services
install -D -p -m 0644 %{S:4} %{buildroot}%{_prefix}/lib/firewalld/services/%{name}-rtp.xml

# Install kernel modules-load.d and modprobe.d files
mkdir -p -m 0755 %{buildroot}%{_prefix}/lib/modules-load.d
mkdir -p -m 0755 %{buildroot}%{_prefix}/lib/modprobe.d
install -D -p -m 0644 kernel-module/xt_RTPENGINE.modules.load.d %{buildroot}%{_prefix}/lib/modules-load.d/xt_RTPENGINE.conf

# Install recording daemon
install -D -p -m 755 recording-daemon/%{name}-recording %{buildroot}%{_sbindir}/%{name}-recording

# Install man page
install -D -p -m 0644 daemon/%{name}.8 %{buildroot}%{_mandir}/man8/%{name}.8

# Install command line interface
install -D -p -m 755 utils/%{name}-ctl %{buildroot}%{_sbindir}/%{name}-ctl

# Create directories for PCAP and WAV recordings
mkdir -p -m 0700 %{buildroot}%{_localstatedir}/spool/rtpengine
mkdir -p -m 0700 %{buildroot}%{_localstatedir}/lib/rtpengine-recording

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
sed -i -e "s/ngcp-rtpengine/rtpengine/g" %{buildroot}%{_usrsrc}/%{name}-%{version}-%{release}/dkms.conf


%pre
%{_sbindir}/useradd --comment "Sipwise NGCP rtpengine Daemon User" \
  --home /run/rtpengine --shell /sbin/nologin --system \
  --user-group rtpengine &>/dev/null || :


%pre kernel
# Update modeprobe.d option file with uid and gid of rtpengine user
export PROC_UID=`id -u rtpengine`
export PROC_GID=`id -g rtpengine`
cat <<EOF > %{_prefix}/lib/modprobe.d/xt_RTPENGINE.conf
options xt_RTPENGINE proc_uid=$PROC_UID proc_gid=$PROC_GID
EOF


%post
%systemd_post %{name}.service
%tmpfiles_create %{name}.conf


%post recording-daemon
%systemd_post %{name}-recording.service


%post dkms
# Add to DKMS registry, build, and install module
dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade &&
dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --force
true


%preun
%systemd_preun %{name}.service

%preun dkms
# Remove from DKMS registry
dkms remove -m %{name} -v %{version}-%{release} --rpm_safe_upgrade --all
true

%preun recording-daemon
%systemd_preun %{name}-recording.service


%postun
%systemd_postun_with_restart %{name}.service


%postun recording-daemon
%systemd_postun_with_restart %{name}-recording.service


%files
%doc README.md
%license LICENSE debian/copyright
%dir %attr(0755, rtpengine, rtpengine) %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%{_mandir}/man8/%{name}.8*
%{_sbindir}/%{name}
%{_sbindir}/%{name}-ctl
%{_unitdir}/%{name}.service
%{_tmpfilesdir}/%{name}.conf
%dir %attr(0700, rtpengine, rtpengine) %{_localstatedir}/spool/rtpengine


%files kernel
%{_libdir}/xtables/libxt_RTPENGINE.so
%{_prefix}/lib/modules-load.d/xt_RTPENGINE.conf
%ghost %{_prefix}/lib/modprobe.d/xt_RTPENGINE.conf


%files firewalld
%{_prefix}/lib/firewalld/services/%{name}-rtp.xml


%files recording-daemon
%{_sbindir}/%{name}-recording
%{_unitdir}/%{name}-recording.service
%dir %attr(0700, rtpengine, rtpengine) %{_localstatedir}/lib/rtpengine-recording

%files dkms
%{_usrsrc}/%{name}-%{version}-%{release}/

%changelog
* Fri May 03 2019 Kevin Doren <kevind@avaya.com>
- Add kernel mod DKMS support for CentOS 7

* Sat Apr 27 2019 Anthony Messina <amessina@messinet.com> - 7.2.1.4-2.gita4cca5f
- Apply master branch updates through a4cca5f

* Thu Apr 04 2019 Anthony Messina <amessina@messinet.com> - 7.2.1.4-1.gitac825cc
- Rebase on top of release 7.2.1.4
- Apply master branch updates through ac825cc

* Sat Mar 30 2019 Anthony Messina <amessina@messinet.com> - 7.2.1.3-1.gitec8df35
- Rebase on top of release 7.2.1.3
- Apply master branch updates through ec8df35
- Remove -E --no-log-timestamps in systemd service files (not necessary with Type=notify)

* Mon Mar 25 2019 Anthony Messina <amessina@messinet.com> - 7.2.1.2-2.git32c0f76
- Apply master branch updates through 32c0f76
- Use -E --no-log-timestamps in systemd service files

* Wed Mar 13 2019 Anthony Messina <amessina@messinet.com> - 7.2.1.2-1.gitf01568e
- Rebase on top of release 7.2.1.2
- Apply master branch updates through f01568e

* Fri Mar 08 2019 Anthony Messina <amessina@messinet.com> - 7.1.1.2-3.git9eea6b1
- Apply master branch updates through 9eea6b1

* Thu Feb 28 2019 Anthony Messina <amessina@messinet.com> - 7.1.1.2-2.git6092c91
- Apply master branch updates through 6092c91

* Sat Feb 23 2019 Anthony Messina <amessina@messinet.com> - 7.1.1.2-1.git717021a
- Rebase on top of release 7.1.1.2
- Apply master branch updates through 717021a

* Sat Feb 16 2019 Anthony Messina <amessina@messinet.com> - 7.1.1.1-2.git88c81be
- Apply master branch updates through 88c81be

* Sun Jan 27 2019 Anthony Messina <amessina@messinet.com> - 7.1.1.1-1.gitff3b821
- Rebase on top of release 7.1.1.1
- Apply master branch updates through ff3b821
- Trim %%changelog

* Sat Jan 19 2019 Anthony Messina <amessina@messinet.com> - 7.0.1.1-4.git0c559f5
- Apply master branch updates through 0c559f5

* Sun Jan 13 2019 Anthony Messina <amessina@messinet.com> - 7.0.1.1-3.git5c556ef
- Apply master branch updates through 5c556ef

* Sat Dec 22 2018 Anthony Messina <amessina@messinet.com> - 7.0.1.1-2.gitaaf8cbd
- Apply master branch updates through aaf8cbd

* Fri Dec 14 2018 Anthony Messina <amessina@messinet.com> - 7.0.1.1-1.git8c9febd
- Rebase on top of release 7.0.1.1
- Apply master branch updates through 8c9febd
