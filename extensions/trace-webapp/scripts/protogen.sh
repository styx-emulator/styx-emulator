#!/bin/bash
GENERATED_SOURCE_DIR=$1
shift
PROTO_SRC_DIRS=("$@")

# Does not actually run protoc, but rather the exit code can tell
# the caller if they are out of date.
# exit non-zero if there are any proto files newer than generated '*.js' files,
# or if there are no generated js files.
# exit 0 otherwise (proto gen up-to-date)
[[ -d ${GENERATED_SOURCE_DIR} ]] || mkdir -p "${GENERATED_SOURCE_DIR}"
newest_jsfile=$(/bin/ls "${GENERATED_SOURCE_DIR}"/*.js 2>/dev/null|head -1)

[[ -z "${newest_jsfile}" ]] && {
    echo "no js files in $GENERATED_SOURCE_DIR"
    exit 1
}

newer_proto_file_count=$(
    find "${PROTO_SRC_DIRS[@]}" \
        -name '*.proto' -newer "$newest_jsfile"  | wc -l
)

(( newer_proto_file_count > 0 )) && {
    echo "${newer_proto_file_count} modified proto files"
    exit 1
}
echo "protos up to date"
exit 0
