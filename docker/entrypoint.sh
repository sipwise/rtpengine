#!/bin/bash
set -e

PATH=/usr/local/bin:$PATH

case $CLOUD in
  gcp)
    LOCAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip)
    PUBLIC_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
    ;;
  aws)
    LOCAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
    ;;
  scaleway)
    LOCAL_IP=$(curl -s --local-port 1-1024 http://169.254.42.42/conf | grep PRIVATE_IP | cut -d = -f 2)
    PUBLIC_IP=$(curl -s --local-port 1-1024 http://169.254.42.42/conf | grep PUBLIC_IP_ADDRESS | cut -d = -f 2)
    ;;
  digitalocean)
    LOCAL_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address)
    PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
    ;;
  azure)
    LOCAL_IP=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text")
    PUBLIC_IP=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text")
    ;;
  *)
    ;;
esac

if [ -n "$PUBLIC_IP" ]; then
  MY_IP="$LOCAL_IP"!"$PUBLIC_IP"
elif [ -n "$LOCAL_IP" ]; then
  MY_IP="$LOCAL_IP"
else
  MY_IP=$(hostname -I | cut -f1 -d' ')
  LOCAL_IP="$MY_IP"
fi

sed -i -e "s:\(interface=.*\)MY_IP:\1$MY_IP:g" rtpengine.conf
sed -i -e "s/MY_IP/$LOCAL_IP/g" rtpengine.conf

if [ "$1" = 'rtpengine' ]; then
  shift
  exec rtpengine --config-file rtpengine.conf  "$@"
fi

exec "$@"
