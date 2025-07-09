#!/bin/bash

# Make sure dockeringore file is ignoring all non-git files for
# the build context

docker image build --no-cache -t build-context -f - . <<EOF
FROM busybox
WORKDIR /build-context
COPY . .
CMD find . -type f
EOF

echo
echo
FILES=($(
    docker run -t --rm build-context 2>&1 | sed -e "s/^\.\///" | dos2unix
))

for file in ${FILES[@]};
do
    git ls-files --error-unmatch $file > /dev/null 2>&1 || {
        echo WARNING: $file is not a tracked file
    }
done
