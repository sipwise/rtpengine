#! /bin/bash
# Sample build script to package RPM using mock
# Usage: el/build-with-mock.sh <package-version> <git-commit>
#
#  el/build-with-mock.sh 12.1.0.0+0~mr12.1.0.0 master


set -e

if [[ -z $1 || -z $2 ]]; then
    echo "$0: Require package version and git commit"
    echo "Usage: build-with-mock.sh <version> <commit>"
    exit 1
fi

RTPENGINE_VERSION=$1
GIT_COMMIT=$2

mkdir -p rpmbuild/{SOURCES,SPECS}

git archive --format=tar --prefix="ngcp-rtpengine-${RTPENGINE_VERSION}/" \
  "${GIT_COMMIT}" \
  | gzip -c >"rpmbuild/SOURCES/ngcp-rtpengine-${RTPENGINE_VERSION}.tar.gz"

sed /^Version/s"/^Version:.*/Version: ${RTPENGINE_VERSION}/" el/rtpengine.spec \
  >rpmbuild/SPECS/rtpengine.spec

rm -f rpmbuild/SRPMS/*.src.rpm
rpmbuild --define "_topdir $PWD/rpmbuild" -bs rpmbuild/SPECS/rtpengine.spec

echo  =======================================
echo "You may now build for EL8/EL9"


echo "EL8: mock -r el/rtpengine-8-x86_64.cfg $(ls rpmbuild/SRPMS/*.src.rpm)"
echo "EL9: mock -r el/rtpengine-9-x86_64.cfg $(ls rpmbuild/SRPMS/*.src.rpm)"
echo  =======================================
