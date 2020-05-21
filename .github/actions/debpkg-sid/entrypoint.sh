#!/bin/bash
set -eu -o pipefail

echo "*** Starting execution of '$0' ***"

echo "** Dropping libbcg729-dev from Build-Depends **"
sed -i '/libbcg729-dev/d' debian/control

echo "** Installing build dependencies **"
apt-get -y build-dep .

echo "** Building Debian package **"
dpkg-buildpackage -Ppkg.ngcp-rtpengine.nobcg729

# We're inside /github/workspace/
echo "** Copying Debian package files to workspace **"
cp ../*.deb ../*.buildinfo  ../workspace/

echo "*** Finished execution of '$0' ***"
