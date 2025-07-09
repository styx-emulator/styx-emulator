GHIDRA_INSTALL_DIR := $(GHIDRA_INSTALL_DIR)
CI_PROJECT_DIR := $(or $(CI_PROJECT_DIR), `pwd`)
GRADLE_USER_HOME := $(or $(GRADLE_USER_HOME), $(HOME)/.gradle)
GRADLE_OPTS := $(or $(GRADLE_OPTS), -q --build-cache --project-cache-dir $(GRADLE_USER_HOME))
GRADLE_CMD := gradle $(GRADLE_OPTS)
JAVA_PROTO_GEN_SRC :=  TyphunixPlugin/src/main/java/typhunix_interop/GhidraState.java TyphunixPlugin/src/main/grpc/typhunix_interop/TyphunixGrpc.java

TYPHUNIX_PKG_LIST := \
	-p typhunix-macros \
	-p typhunix-proto \
	-p typhunix-server-bin \
	-p typhunix-client-bin \
	-p typhunix-python-bindings \
	-p typhunix-config


default: build

################################################################################
## dev targets - misc helpers
################################################################################

# Make sure GHIDRA_INSTALL_DIR is set
env-check:
	@if [ ! -d "$(GHIDRA_INSTALL_DIR)" ]; then \
		echo "Must set and export GHIDRA_INSTALL_DIR" 1>&2 ;\
	    exit 1;\
	fi
# Eclipse for vscode and eclipse dev - regenerates eclipse projects
eclipse: build-plugin
	gradle --project-cache-dir $(GRADLE_USER_HOME) :TyphunixPlugin:eclipse

# show gradle tasks
show_tasks:
	$(GRADLE_CMD) tasks
# show env vars
show_env:
	@echo GHIDRA_INSTALL_DIR: $(GHIDRA_INSTALL_DIR)
	@echo CI_PROJECT_DIR: $(CI_PROJECT_DIR)
	@echo GRADLE_USER_HOME: $(GRADLE_USER_HOME)
	@echo GRADLE_OPTS: $(GRADLE_OPTS)
	@echo GRADLE_CMD: $(GRADLE_CMD)
	@echo MINIO_ALIAS: $(MINIO_ALIAS)
	@echo MINIO_HOST: $(MINIO_HOST)
	@echo MINIO_ACCESS_KEY: $(MINIO_ACCESS_KEY)

################################################################################
## build / compile  targets
################################################################################

# TyphunixPlugin - skip tests
build-plugin: env-check build-typhunix-proto
	$(GRADLE_CMD) -x test :TyphunixPlugin:build :TyphunixPlugin:buildExtension :TyphunixPlugin:eclipse
	./scripts/normalize_extension_names.sh

typhunix-plugin-build-ext: env-check
	$(GRADLE_CMD) -x test :TyphunixPlugin:build :TyphunixPlugin:buildExtension :TyphunixPlugin:eclipse
	./scripts/normalize_extension_names.sh

# build the proto lib
build-typhunix-proto:
	cargo build -p typhunix-proto

# build the grpc server
build-server:
	cargo build -p typhunix-server-bin

# build client program
build-client:
	cargo build -p typhunix-client-bin

# dev pythphunix
bindings:
	# pip installs in a transient but immediate fashion
	cargo   build -p typhunix-python-bindings --features pyo3_bindings
	maturin develop --manifest-path rust/typhunix-python-bindings/Cargo.toml

# build pythphunix (debug)
build-pythphunix:
	cargo   build -p typhunix-python-bindings --features pyo3_bindings
	maturin build --manifest-path rust/typhunix-python-bindings/Cargo.toml

install-pythphunix: build-pythphunix
	pip install --force-reinstall ../../target/wheels/pytyphunix-0.1.0-cp310-cp310-manylinux_2_34_x86_64.whl


# build all the debug rust
build-rust-all: build-typhunix-proto build-server build-client build-pythphunix

cargo-build-release:
	cargo build $(TYPHUNIX_PKG_LIST) --release

cargo-test-release:
	cargo test  $(TYPHUNIX_PKG_LIST) --release
	cargo doc   $(TYPHUNIX_PKG_LIST) --release

wheel-release:
	cargo build $(TYPHUNIX_PKG_LIST) --release --features pyo3_bindings
	maturin build --manifest-path rust/typhunix-python-bindings/Cargo.toml --release

build-release:
	cargo build $(TYPHUNIX_PKG_LIST) --release --features pyo3_bindings
	cargo test  $(TYPHUNIX_PKG_LIST) --release --features pyo3_bindings
	cargo doc   $(TYPHUNIX_PKG_LIST) --release --features pyo3_bindings
	maturin build --manifest-path rust/typhunix-python-bindings/Cargo.toml --release

build: build-rust-all build-plugin

################################################################################
## shortcuts for running things
################################################################################

# run the grpc server
run-server:
	cargo run --bin typhunix-server

################################################################################
## quality checks
################################################################################
quality-check-rust:
	cargo check $(TYPHUNIX_PKG_LIST)
	cargo clippy $(TYPHUNIX_PKG_LIST)  -- -D warnings

quality-check-java:
	$(GRADLE_CMD) -x test :TyphunixPlugin:spotlessCheck

quality-check-rustfmt:
	cargo fmt $(TYPHUNIX_PKG_LIST) --all --check


quality-check: quality-check-rust quality-check-java quality-check-rustfmt

pre-commit-install:
	pre-commit install

pre-commit-run:
	pre-commit run -a

################################################################################
## run tests
################################################################################
test-all-rust:
	cargo test $(TYPHUNIX_PKG_LIST)
	cargo doc $(TYPHUNIX_PKG_LIST)

test-integration:
	$(GRADLE_CMD) :TyphunixPlugin:test --tests typhunix_plugin.TyphunixPluginIntegrationTest.testIntegrationTest

test-plugin: build-plugin
	$(GRADLE_CMD) :TyphunixPlugin:test

gitlab-test:
	@echo "PLUGIN (java)"
	$(GRADLE_CMD) :TyphunixPlugin:test
	@echo "RUST tests"
	cargo test $(TYPHUNIX_PKG_LIST)
	@echo "RUST doc"
	cargo doc $(TYPHUNIX_PKG_LIST)

test:
	scripts/run_test.sh

################################################################################
## cleaning up
################################################################################

clean-plugin:
	gradle -q --project-cache-dir $(GRADLE_USER_HOME) :TyphunixPlugin:cleanEclipse
	rm -rf build/
	@for d in bin lib dist build src/main/grpc .settings; \
		do rm -rf TyphunixPlugin/$${d};\
	done
	rm -rf $(JAVA_PROTO_GEN_SRC)

clean-rust:
	cargo clean $(TYPHUNIX_PKG_LIST)

clean: clean-rust clean-plugin

download-ghidra:
	scripts/download_ghidra.sh

################################################################################
## Docker image targets
################################################################################
image-ci:
	make -C docker/ci

image-ci-no-cache:
	make -C docker/ci build-no-cache

image-ci-push:
	make -C docker/ci build push

################################################################################
## package / release
################################################################################
package: # build test build-release
	@echo "Assuming make build test build-release"
	@echo "Running scripts/package.sh"
	scripts/package.sh

release:
	scripts/push_release.sh
