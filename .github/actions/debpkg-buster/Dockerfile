FROM debian:buster

COPY entrypoint.sh /entrypoint.sh

# avoid "debconf: (TERM is not set, so the dialog frontend is not usable.)"
ENV DEBIAN_FRONTEND noninteractive

# disable man-db to speed up builds
RUN echo 'man-db man-db/auto-update boolean false' | debconf-set-selections

RUN apt-get update && apt-get -y install build-essential

ENTRYPOINT ["/entrypoint.sh"]
