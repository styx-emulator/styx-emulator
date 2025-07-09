#!/bin/bash

set -e
mc alias ls ${MINIO_ALIAS} > /dev/null 2>&1 || {
    mc alias set "${MINIO_ALIAS}" "${MINIO_HOST}" \
        "${MINIO_ACCESS_KEY}" "${MINIO_SECRET_KEY}" \
        --api "s3v4" --path "auto"
    echo "Set minio alias ${MINIO_ALIAS} for ${MINIO_ACCESS_KEY}@${MINIO_HOST}" 1>&2
}

chmod 600 ~/.mc/config.json || echo "WARNING: failed chmod 600 ~/.mc/config.json"
