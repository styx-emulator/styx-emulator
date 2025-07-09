PACKAGE := typhunix-ci
TAG := $(or $(or $(or $(CI_COMMIT_BRANCH),$(CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)),$(TAG)),dev) # default to dev tag
BUILD_CONTEXT := ../../
DOCKERFILE := `pwd`/Dockerfile
BRANCH_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):$(TAG)
MAIN_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):main
LATEST_IMAGE_NAME := $(CI_REGISTRY_IMAGE)/$(PACKAGE):latest
BUILD_ARGS := --build-arg RUST_VERSION=$(shell cat ../../../../.rust-version)
DOCKER_BUILD := docker build -f $(DOCKERFILE) -t $(BRANCH_IMAGE_NAME) $(BUILD_CONTEXT) $(BUILD_ARGS)

all: build ci-build

build-no-cache:
	$(DOCKER_BUILD) --no-cache

build:
	$(DOCKER_BUILD)

ci-build:
ifneq ($(REBUILD_IMAGE),) # REBUILD_IMAGE IS SET
	$(DOCKER_BUILD) # build new image for branch
else
	docker pull $(MAIN_IMAGE_NAME)
	docker tag $(MAIN_IMAGE_NAME) $(BRANCH_IMAGE_NAME) # tag branch image as main
endif

push:
	docker push $(BRANCH_IMAGE_NAME) # push branch
ifeq ($(BRANCH_IMAGE_NAME),$(MAIN_IMAGE_NAME)) # branch == main
	docker tag $(BRANCH_IMAGE_NAME) $(LATEST_IMAGE_NAME)
	docker push $(LATEST_IMAGE_NAME) # force update latest tag on server
endif

.PHONY: build push build-no-cache ci-build
