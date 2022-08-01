#!/bin/sh
# generate templates
for i in ngcp-rtpengine-daemon ngcp-rtpengine-recording-daemon; do
  sed \
    -e 's:daemon\.pid:daemon.%i.pid:g' \
    -e 's:/etc/rtpengine/:/etc/rtpengine_%i/:g' \
    $i.service > $i@.service
done
