FROM debian:trixie-slim AS build

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  default-libmysqlclient-dev \
  g++ \
  gcc \
  git \
  gperf \
  iproute2 \
  iptables \
  libavcodec-extra \
  libavfilter-dev \
  libcurl4-openssl-dev \
  libevent-dev \
  libhiredis-dev \
  libiptc-dev \
  libjson-glib-dev \
  libjwt-dev \
  libmnl-dev \
  libncursesw5-dev \
  libnftnl-dev \
  libopus-dev \
  libpcap-dev \
  libpcre2-dev \
  libspandsp-dev \
  libssl-dev \
  libwebsockets-dev \
  make \
  markdown \
  patch

WORKDIR /usr/src/rtpengine
COPY . .

FROM build AS rtpengine
WORKDIR /usr/src/rtpengine/daemon
RUN make -j$(nproc) rtpengine && \
  strip -o /usr/local/bin/rtpengine rtpengine

FROM build AS rtpengine-recording
WORKDIR /usr/src/rtpengine/recording-daemon
RUN make -j$(nproc) rtpengine-recording && \
  strip -o /usr/local/bin/rtpengine-recording rtpengine-recording

FROM debian:trixie-slim

VOLUME ["/rec"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["rtpengine"]

EXPOSE 23000-65535/udp 22222/udp

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl \
  iproute2 \
  iptables \
  libglib2.0-0 \
  libavcodec-extra \
  libavfilter10 \
  libcurl4 \
  libevent-2.1-7 \
  libevent-pthreads-2.1-7 \
  libhiredis1.1.0 \
  libip6tc2 \
  libjson-glib-1.0-0 \
  libjwt2 \
  libmariadb3 \
  libmnl0 \
  libncursesw6 \
  libnftnl11 \
  libopus0 \
  libpcap0.8 \
  libpcre2-8-0 \
  libspandsp2 \
  libssl3 \
  libwebsockets19 \
  net-tools \
  procps \
  sudo \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=rtpengine /usr/local/bin/rtpengine /usr/local/bin/
COPY --from=rtpengine-recording /usr/local/bin/rtpengine-recording /usr/local/bin/
COPY docker/entrypoint.sh /entrypoint.sh
RUN echo '%sudo   ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/nopasswd && \
  groupadd --gid 1000 rtpengine && \
  useradd --uid 1000 --gid rtpengine -G sudo --shell /bin/bash --create-home rtpengine
USER rtpengine
WORKDIR /home/rtpengine
COPY docker/rtpengine.conf .
