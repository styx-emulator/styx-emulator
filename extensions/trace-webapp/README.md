# Web app for Emulations

An angular app for running styx emulations and visualizing trace messages. Build with `Angular v17.x`

## Ghidra Plugin - Typhunix

Build and install the typhunix plugin (see the [README](../../extensions/typhunix/README.md)).
The webapp does not send events for raw memory addresses - only those associated with a named symbols (this limitation is being removed). Alternatively, download the plugin from *TODO*.

## Running

You can run the webapp either natively (linux only) or using docker,
these instructions assume:

- `direnv` is setup and your repo (styx-emulator) is allowed
- repo (styx-emulator) RUST builds are done natively

*Note: in either native or docker environments, the slow part is usually building
the angular app. It's not really capabile of serving content until you see
*Compiled successfully*. At that point, you can open a browser to `https://localhost:4200`.
(in serve mode, rebuilds are quick)*

The script `webapp.sh` can be used to start, stop, get status.

### Running in Docker

The first docker build is very slow - it needs to build and pull containers.

```bash
export SERVE_ENV=docker # docker is the default
cd ${CI_PROJECT_DIR}
webapp.sh up # (adds -d flag for docker-compose)
```

### Envoy Proxy

The envoy proxy is the gateway to backend services and is
set based on the values of `ENVOY_URL_HOST` and `ENVOY_URL_PORT` which default to `127.0.0.1` and `8080` respectively. Override
these variables as needed. For example if your port `8080` is already in use or if your docker stack is running on a remote host (different than your browser):

```bash
export ENVOY_URL_PORT=7000
export ENVOY_URL_HOST=192.168.32.19
cd ${CI_PROJECT_DIR}
webapp.sh up # (adds -d flag for docker-compose)
```

### Running Natively

You need an Angular v17 webstack and envoy proxy. Make sure you have all the dependencies: See the [Installing Dependencies](#installing-dependencies) section.

Its a good idea to do a full build first. If running the browser on the same machine as the services then everything can run on `https://127.0.0.1`:

```bash
export SERVE_ENV=local
cd ${CI_PROJECT_DIR}
webapp.sh up # blocks on serving http requests
```

## Developing

### Code scaffolding

Run `ng generate component component-name` to generate a new component. You can also use `ng generate directive|pipe|service|class|guard|interface|enum|module`.

### Build

Run `ng build` to build the project. The build artifacts will be stored in the `dist/` directory.

### Running unit tests

(Currently broken)

Run `ng test` to execute the unit tests via [Karma](https://karma-runner.github.io).

### Running end-to-end tests

(Currently broken)

Run `ng e2e` to execute the end-to-end tests via a platform of your choice. To use this command, you need to first add a package that implements end-to-end testing capabilities.

## Further help

To get more help on the Angular CLI use `ng help` or go check out the [Angular CLI Overview and Command Reference](https://angular.io/cli) page.

## Installing Dependencies

To build and run locally, you'll need the `ng` (angular cli v17), `nodejs` which is an `npm` package, and the envoy proxy server.

Angular v17 supports:

- node.js versions: v18.13.0 and newer `node -v`
- typescript v5.2 or later `tsc -v`
- zone.js v0.14.x or later (`npm list | grep -i zone)

You will also need the google protocol buffer compiler and plugins for `grpc-web`, `protoc-gen-grpc-web` , `protoc-gen-js` , and `protoc-gen-ts`.

### protoc

Look at the [ci.Dockerfile](../../docker/ci.Dockerfile).

### envoy proxy

Available as a binary - download and place somewhere in your path.

- Downloads: <https://github.com/envoyproxy/envoy/releases/tag/v1.29.2>
- Binary Download: <https://github.com/envoyproxy/envoy/releases/download/v1.29.2/envoy-1.29.2-linux-x86_64>

### node and angular

Installing node will also install the package manager `npm`.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
    sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
NODE_MAJOR=20
deburl=https://deb.nodesource.com/node_$NODE_MAJOR.x
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] ${deburl} nodistro main" | \
    sudo tee /etc/apt/sources.list.d/nodesource.list

sudo apt-get update
sudo apt-get install nodejs -y
```

### Global Node Packages

```bash
sudo npm install -g '@angular/cli' \
    grpc-web protoc-gen-grpc-web \
    protoc-gen-js \
    protoc-gen-ts
```

Here are my versions of global `npm` packages, typescript is
not required to be a global package.

```bash
$ npm list -g
/usr/lib
├── @angular/cli@17.3.0
├── corepack@0.23.0
├── grpc-web@1.5.0
├── npm@10.2.4
├── protoc-gen-grpc-web@1.4.2
├── protoc-gen-js@3.21.2
├── protoc-gen-ts@0.8.7
└── typescript@5.4.2
```

## ESLINT

Check configuration:

```bash
npx eslint --print-config .eslintrc.js
```
