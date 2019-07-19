FROM centos:latest

#ENV Project "$HOME/rtpengine"

#COPY . $Project

RUN yum -y update 
RUN yum -y install epel-release 
RUN yum -y install gcc make pkgconfig redhat-rpm-config rpm-build glib2-devel libcurl-devel pcre-devel
RUN yum -y --enablerepo=updates install openssl-devel systemd-devel
RUN yum -y install xmlrpc-c-devel zlib-devel hiredis-devel libpcap-devel libevent-devel json-glib-devel shadow-utils nc mysql-devel spandsp-devel
RUN yum -y localinstall --nogpgcheck https://download1.rpmfusion.org/free/el/rpmfusion-free-release-7.noarch.rpm
RUN rpm --import http://li.nux.ro/download/nux/RPM-GPG-KEY-nux.ro
RUN rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm
RUN yum -y install ffmpeg ffmpeg-libs ffmpeg-devel
RUN yum -y install iptables iptables-ipv6 dkms iptables-devel gperf perl-generators perl-IPC-Cmd

CMD ["/bin/bash"]
