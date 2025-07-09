CRATE_DIR=../../../target/release
libstyx_c_api_shared=$(CRATE_DIR)/libstyx_c_api.so
libstyx_c_api_static=$(CRATE_DIR)/libstyx_c_api.a
SHARED_TARGET=main-shared.bin
STATIC_TARGET=main-static.bin
INCLUDE=-I../../inc/
LINK_DIR=-L$(CRATE_DIR)
LINK_FLAGS=$(LINK_DIR) -lc -lm -lstdc++
SHARED_LINK_FLAGS=-lstyx_c_api $(LINK_FLAGS)
STATIC_LINK_FLAGS=-l:libstyx_c_api.a $(LINK_FLAGS)
SRC=main.c
CFLAGS=-Wall -Wextra -Wpedantic -std=c11 -g
CC?=gcc

.PHONY: build clean run-static run-shared


# NOTE: styx libraries are sourced from RELEASE

build: $(SHARED_TARGET) $(STATIC_TARGET)

run-static: $(STATIC_TARGET)
	./$(STATIC_TARGET)

run-shared: $(SHARED_TARGET)
	LD_LIBRARY_PATH="$(CRATE_DIR):$(LD_LIBRARY_PATH)" ./$(SHARED_TARGET)

$(libstyx_c_api_shared):
	just c-bindings

$(libstyx_c_api_static):
	just c-bindings

$(SHARED_TARGET): $(libstyx_c_api_shared) $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(SHARED_TARGET) $(INCLUDE) $(LINK_DIR) $(SHARED_LINK_FLAGS)

$(STATIC_TARGET): $(libstyx_c_api_static) $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(STATIC_TARGET) $(INCLUDE) $(LINK_DIR) $(STATIC_LINK_FLAGS)

clean:
	@rm -f $(SHARED_TARGET) $(STATIC_TARGET)
