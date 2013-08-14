Name:		mediaproxy-ng
Version:	2.3.0
Release:	1%{?dist}
Summary:	The Sipwise NGCP mediaproxy-ng

Group:		System Environment/Daemons
License:	unknown
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
Summary:	In-kernel package forwarding support for mediaproxy-ng
Group:		System Environment/Daemons
BuildRequires:	iptables-devel
Requires:	iptables iptables-ipv6 mediaproxy-ng = %{version}

%description kernel
iptables plugin and kernel module for mediaproxy-ng in-kernal package forwarding


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
#mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d
#install -m755 el/mediaproxy-ng.init \
#	$RPM_BUILD_ROOT/%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
#mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
#install -m644 el/mediaproxy-ng.sysconfig \
#	$RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/mediaproxy-ng

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


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r mediaproxy-ng 2> /dev/null || :
/usr/sbin/usradd -r -g mediaproxy-ng -s /bin/false -c "mediaproxy-ng daemon" \
	-d %{_docdir}/%{name}-%{version}-%{release} mediaproxy-ng \
	2> /dev/null || :


#%post
#/sbin/chkconfig --add mediaproxy-ng
#
#
#%preun
#/sbin/service mediaproxy-ng stop
#/sbin/chkconfig --del mediaproxy-ng


%files
%defattr(-,root,root,-)
# Userspace daemon
%{_sbindir}/mediaproxy-ng

# init.d script and configuration file
#%{_sysconfdir}/rc.d/init.d/mediaproxy-ng
#%{_sysconfdir}/sysconfig/mediaproxy-ng

# Documentation
%dir %{_docdir}/%{name}-%{version}-%{release}
%doc %{_docdir}/%{name}-%{version}-%{release}/README.md
%doc %{_docdir}/%{name}-%{version}-%{release}/changelog
%doc %{_docdir}/%{name}-%{version}-%{release}/copyright
%doc %{_docdir}/%{name}-%{version}-%{release}/README.el.md


%files kernel
/%{_lib}/xtables/libxt_MEDIAPROXY.so


%changelog
* Wed Aug 14 2012 Peter Dunkley <peter.dunkley@crocodilertc.net>
  - First version of .spec file
  - Builds and installs userspace daemon (but no init.d scripts etc yet)
  - Builds and installs the iptables plugin (but no kernel module yet)
