FROM centos:latest

RUN yum -y update && \
    yum -y install epel-release && \
    yum -y install gcc make pkgconfig redhat-rpm-config rpm-build glib2-devel libcurl-devel pcre-devel  && \
    yum -y --enablerepo=updates install openssl-devel systemd-devel && \
    yum -y install xmlrpc-c-devel zlib-devel hiredis-devel libpcap-devel libevent-devel json-glib-devel shadow-utils nc mysql-devel spandsp-devel && \
    yum -y localinstall --nogpgcheck https://download1.rpmfusion.org/free/el/rpmfusion-free-release-7.noarch.rpm && \
    yum -y install ffmpeg ffmpeg-libs ffmpeg-devel && \
    yum -y install iptables iptables-ipv6 dkms iptables-devel gperf perl-generators perl-IPC-Cmd

CMD ["/bin/bash"]