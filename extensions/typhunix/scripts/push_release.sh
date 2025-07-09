#!/bin/bash

set -e
VERSION=${VERSION:-Typhunix-$(scripts/version.sh)}
scripts/setup_minio.sh
TARBALL=${VERSION}.tgz
TARBALL_MD5=${TARBALL}.md5

if [[ "$(md5sum $TARBALL)" != $(< ${TARBALL_MD5}) ]]; then
    echo "Error: md5 check failed" 1>&2
    exit 1
fi

cmd=(mc cp -q ${TARBALL} ${TARBALL_MD5} ${MINIO_ALIAS}/typhunix/Releases)
echo "+ ${cmd[@]}" 1>&2
${cmd[@]}

mc tree -f ${MINIO_ALIAS}/typhunix/Releases

echo OK
