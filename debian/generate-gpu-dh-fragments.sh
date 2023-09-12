#!/bin/bash
for pkg in ngcp-rtpengine-daemon ngcp-rtpengine-recording-daemon ngcp-rtpengine-perftest; do
  for file in "$pkg".*; do
    if test -f "$file"; then
      suffix=${file#"$pkg".}
      cp -v "$pkg"."$suffix" "$pkg"-gpu."$suffix"
    fi
  done
  for file in "$pkg"@.*; do
    if test -f "$file"; then
      suffix=${file#"$pkg"@.}
      cp -v "$pkg"@."$suffix" "$pkg"-gpu@."$suffix"
    fi
  done
  if test -f "$pkg"-gpu.links; then
    rm -vf "$pkg"-gpu.links.tmp
    while read -r line; do
      # rewrite link from original 'rtpengine-daemon.service -> ngcp-rtpengine-daemon.service'
      # ... to 'rtpengine-daemon-gpu.service -> ngcp-rtpengine-daemon-gpu.service'
      echo "$line" | sed 's/\(@\?\)\.service/-gpu\1.service/g' >> "$pkg"-gpu.links.tmp
      # add link 'rtpengine-daemon.service -> ngcp-rtpengine-daemon-gpu.service'
      echo "$line" | sed 's/\(@\?\)\.service/-gpu\1.service/' >> "$pkg"-gpu.links.tmp
      # add link 'ngcp-rtpengine-daemon.service -> ngcp-rtpengine-daemon-gpu.service'
      echo "$line" | sed 's/\(@\?\)\.service/-gpu\1.service/; s,system/rtpengine,system/ngcp-rtpengine,' >> "$pkg"-gpu.links.tmp
    done < "$pkg"-gpu.links
    mv -v "$pkg"-gpu.links.tmp "$pkg"-gpu.links
  fi
done
