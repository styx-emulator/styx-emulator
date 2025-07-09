FROM node:latest as node

RUN apt-get update && apt-get install -yqq --no-install-recommends inetutils-ping less vim curl make && \
    cd /tmp && wget -nv https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip && \
    unzip protoc-21.5-linux-x86_64.zip && cp bin/* /usr/bin/ && cp -r include/* /usr/include && \
    npm install -g \
    @angular/cli \
    grpc-web \
    protoc-gen-grpc-web \
    protoc-gen-js \
    protoc-gen-ts

# RUN npm install -g '@angular-devkit/build-angular'
# RUN npm install -g "@angular/cli@18.0.3"

WORKDIR /project
ENTRYPOINT [ "/bin/bash", "-c" ]
