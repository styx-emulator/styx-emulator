# CARGO_FLAGS := -q

GENERATED_SOURCE_DIR := $(CI_PROJECT_DIR)/extensions/trace-webapp/src/generated
PROTO_DIR := $(CI_PROJECT_DIR)/styx/idl/proto
ALL_PROTO_SRCDIRS=$(PROTO_DIR)

PROTO_FILES = `find $(ALL_PROTO_SRCDIRS) -name *.proto | xargs -i basename {}`
PROTO_INCLUDE_DIRS = `find $(ALL_PROTO_SRCDIRS) -name "*.proto" | \
					  xargs -i dirname {} | sort -u | sed -e "s/^/-I/"`

ifeq ($(SERVE_ENV), docker)
NPM_DEPENDS := build-containers
COND_MAKE := docker compose run --rm --entrypoint make -w /project/extensions/trace-webapp webapp
COND_EXEC := docker compose run --rm --entrypoint bash -w /project/extensions/trace-webapp webapp
else
COND_MAKE := make --no-print-directory
COND_EXEC := bash -c
endif

build-backend:
	cargo build -p traceapp-service $(CARGO_FLAGS)
	cargo build -p typhunix-server-bin --bin typhunix-server $(CARGO_FLAGS)
	cargo build -p typhunix-client-bin --bin typhunix-client $(CARGO_FLAGS)
	cargo build -p emulation-registry-service $(CARGO_FLAGS)
	cargo build -p emulation-service $(CARGO_FLAGS)
	cargo build -p workspace-service $(CARGO_FLAGS)

build-containers:
	docker compose build

check-proto:
	$(COND_EXEC) -c "scripts/protogen.sh ${GENERATED_SOURCE_DIR} ${ALL_PROTO_SRCDIRS} || make proto"

proto:
	@mkdir -p src/generated
	@echo "*****************************"
	@echo "* protoc: generating javascript files: `uname -n`://`pwd`"
	@echo "*****************************"
	protoc \
		$(PROTO_FILES) \
        $(PROTO_INCLUDE_DIRS) \
		--js_out=import_style=commonjs,binary:src/generated \
		--grpc-web_out=import_style=typescript,mode=grpcwebtext:src/generated

npm: $(NPM_DEPENDS)
	$(COND_MAKE) npmi
npmi:
	@if [ ! -d node_modules ]; then npm install;fi

# build: build-backend # npm check-proto
build:
	@make build-backend
	@make npm
	@make check-proto
