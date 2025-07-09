CI_PROJECT_DIR := $(or $(CI_PROJECT_DIR), `pwd`)
CI_COMMIT_BRANCH := $(or $(CI_COMMIT_BRANCH), `git rev-parse --abbrev-ref HEAD`)
GHIDRA_RELEASE_DIR=${GHIDRA_RELEASE_DIR:-${CI_PROJECT_DIR}}/ghidra-releases

download-ghidra:
	@extensions/typhunix/scripts/download_ghidra.sh

typhunix-test:
	@extensions/typhunix/scripts/build_artifacts.sh

typhunix-ci:
	make -C extensions/typhunix/ image-ci
