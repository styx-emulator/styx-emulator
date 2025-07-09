# TODO: migrate this to a `cargo xtask` script
TAG := $(or $(or $(or $(CI_COMMIT_BRANCH),$(CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)),$(TAG)),dev) # default to dev tag

PACKAGE := $(or $(PACKAGE), styx-ci)
BUILD_CONTEXT := .
DOCKERFILE := $(shell pwd)/ci.Dockerfile
BRANCH_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):$(TAG)
MAIN_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):main
PYTHON_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/styx-python-builder
BRANCH_PYTHON_IMAGE_NAME := $(PYTHON_IMAGE_NAME):$(TAG)
MAIN_PYTHON_IMAGE_NAME := $(PYTHON_IMAGE_NAME):main
LATEST_PYTHON_IMAGE_NAME := $(PYTHON_IMAGE_NAME):latest
LATEST_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):latest
RUST_VERSION := $(shell cat ../../.rust-version)
BUILD_ARGS := --build-arg RUST_VERSION=$(RUST_VERSION)
DOCKER_MAIN_BUILD := docker build -f $(DOCKERFILE) -t $(BRANCH_IMAGE_NAME) $(BUILD_CONTEXT) $(BUILD_ARGS)
DOCKER_PYTHON_BUILD := docker build -f python.Dockerfile -t $(MAIN_PYTHON_IMAGE_NAME) $(BUILD_CONTEXT)

ci-build:
ifneq ($(REBUILD_IMAGE),) # REBUILD_IMAGE IS SET
	$(DOCKER_MAIN_BUILD) # build new image for branch
else
	docker pull $(MAIN_IMAGE_NAME)
	docker tag $(MAIN_IMAGE_NAME) $(BRANCH_IMAGE_NAME) # tag branch image as main
endif

python-build:
ifneq ($(REBUILD_IMAGE),) # REBUILD_IMAGE IS SET
	$(DOCKER_PYTHON_BUILD) # build new image for branch
else
	docker pull $(MAIN_PYTHON_IMAGE_NAME)
	docker tag $(MAIN_PYTHON_IMAGE_NAME) $(BRANCH_PYTHON_IMAGE_NAME) # tag branch image as main
endif

python-push:
	docker push $(BRANCH_PYTHON_IMAGE_NAME) # push branch
ifeq ($(BRANCH_PYTHON_IMAGE_NAME),$(MAIN_PYTHON_IMAGE_NAME)) # branch == main
	docker tag $(BRANCH_PYTHON_IMAGE_NAME) $(LATEST_PYTHON_IMAGE_NAME)
	docker push $(LATEST_PYTHON_IMAGE_NAME) # force update latest tag on server
endif


push:
	docker push $(BRANCH_IMAGE_NAME) # push branch
ifeq ($(BRANCH_IMAGE_NAME),$(MAIN_IMAGE_NAME)) # branch == main
	docker tag $(BRANCH_IMAGE_NAME) $(LATEST_IMAGE_NAME)
	docker push $(LATEST_IMAGE_NAME) # force update latest tag on server
endif

armtools-image:
	docker build -f armtools.Dockerfile . -t armtools:latest

.PHONY: ci-build push armtools-image python-build python-push
