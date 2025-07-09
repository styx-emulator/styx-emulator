#!/bin/bash
export CI_PROJECT_DIR=${CI_PROJECT_DIR:-$(pwd)}
source ${CI_PROJECT_DIR}/extensions/typhunix/scripts/common.sh

if [[ ${CI_COMMIT_BRANCH} == "main" ]]; then
    ACTIVE=${SUPPORTED_GHIDRA[@]}
else
    ACTIVE=(${LATEST_GHIDRA_RELEASE})
fi

[[ -d ${GHIDRA_RELEASE_DIR} ]] || mkdir -p ${GHIDRA_RELEASE_DIR}
for gr in ${ACTIVE[@]}; do
    (
        name=$(echo $gr | cut -d"|" -f1)
        url=$(echo  $gr | cut -d"|" -f2)
        echo URL="$url"
        if [[ ! -d ${GHIDRA_RELEASE_DIR}/$name ]]; then
            rm -f $GHIDRA_RELEASE_DIR/${name}.zip
            echo "Downloading $name ... "
            wget -nv -O $GHIDRA_RELEASE_DIR/${name}.zip  $url
            echo "Unzipping $name ... "
            unzip -q $GHIDRA_RELEASE_DIR/${name}.zip -d $GHIDRA_RELEASE_DIR
        fi
        /bin/ls -ld ${GHIDRA_RELEASE_DIR}/$name
    ) &
done
wait

echo
echo "---"
echo Download/Unzip ghidra done
echo "${GHIDRA_RELEASE_DIR}: "
/bin/ls -l ${GHIDRA_RELEASE_DIR}

echo "---"
echo "==>  [Exit 0] ($0)"; exit 0
