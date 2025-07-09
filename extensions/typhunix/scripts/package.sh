#!/bin/bash
RED="\u001b[31m"
CYN="\u001b[36m"
RST="\u001b[0m"
DIM="\u001b[2m"

set -e
git config --global --add safe.directory /build
VERSION=${VERSION:-Typhunix-$(scripts/version.sh)}

TEMPDIR_ROOT=$(mktemp -d);TEMPDIR=$TEMPDIR_ROOT/$VERSION
trap "rm -rf $TEMPDIR_ROOT " hup int quit exit

# package release versions of these rust binaries
RUST_BINS=(typhunix-server typhunix-client)

# Create the directories to hold artifacts
mkdir -p $TEMPDIR/{bins/release,plugins,wheel}

# PLUGINS
# Take all the ghudra*zip files in dist/
printf "${CYN}+ Packaging Plugin Zips ...\n${RST}"
PLUGIN_ZIPS=($( /bin/ls -1 TyphunixPlugin/dist/ghidra*.zip ))
for p in ${PLUGIN_ZIPS[@]}; do
    printf "${CYN}${DIM}    - $p \n${RST}"
    cp $p $TEMPDIR/plugins
done


# WHEELS for rust python bindings
printf "${CYN}+ Packaging Rust Binding Python Wheels ...\n${RST}"
WHEELS=($(
    /bin/ls -1 rust/target/wheels/*.whl
))
for p in ${WHEELS[@]}; do
    printf "${CYN}${DIM}    - $p \n${RST}"
    cp $p $TEMPDIR/wheel
done

# Rust binaries
printf "${CYN}+ Packaging binaries ...\n${RST}"
for p in ${RUST_BINS[@]}; do
    cp rust/target/release/${p} ${TEMPDIR}/bins/release
    printf "${CYN}${DIM}    - rust/target/release/${p} \n${RST}"
done


# Show contents
printf "${CYN}"
for i in $(seq 80); do printf "=";done; printf "\n"
printf "Package Contents\n"
for i in $(seq 80); do printf "=";done; printf "${RST}\n"
tree -an $TEMPDIR | /usr/bin/pr -n -t

# Create tar ball
printf "${CYN}+ Creating tar ball\n${RST}"
CMD="tar -C ${TEMPDIR_ROOT}  -zcf ${VERSION}.tgz ${VERSION}"
printf "${CYN}${DIM}    $CMD\n${RST}"
$CMD
md5sum ${VERSION}.tgz >  ${VERSION}.tgz.md5

printf "${GRN}Success\n${GRN}"
exit 0
