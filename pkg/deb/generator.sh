#!/bin/bash
# produces non-NGCP pkg/deb/debian from debian

if [ ! -d ../../pkg/deb ] ; then
  echo "script needs to be executed at pkg/deb dir" >&2
  exit 1
fi

rm -rf debian

echo "- Copying origin debian dir"
cp -ra ../../debian .
echo "- Copying backports scripts"
cp -ra backports debian

# rules
echo "- Remove ngcp- prefix"
find debian -maxdepth 1 -type f -exec sed -i -e 's/ngcp-rtpengine/rtpengine/g' {} \;

## remove same file on links
while read -r file; do
  file_new=$(echo "${file}" | sed -e 's/ngcp-//g')
  while read -r line; do
    sed -i -e "s#${line}\$#HH#g" "${file}"
  done < <(awk '{print $1}' "${file}")
  grep -v HH "${file}" > "${file_new}"
  rm "${file}"
done < <(find debian -name '*links')

echo "- Remove NGCP packages from Suggests"
sed -i -e '/ngcp-system-tools/d' debian/control

echo "- Add Conflicts with NGCP packages"
while read -r line ; do
  sed -i "/${line}$/ a Conflicts: ngcp-${line#Package: }" debian/control
done < <(awk '/Package:/' debian/control)

echo "- Rename files"
while read -r file; do
  file_new=$(echo "${file}" | sed -e 's/ngcp-//g')
  mv "${file}" "${file_new}"
done < <(find debian -maxdepth 1 -type f -name 'ngcp-rtpengine*')

echo "- Remove empty Suggests"
wrap-and-sort
sed -i -e '/Suggests:$/d' debian/control
wrap-and-sort -sat
