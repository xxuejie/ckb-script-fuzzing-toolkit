cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)

CLANG := $(shell $(TOP)/scripts/find_clang)
CLANG_FORMAT := $(subst clang,clang-format,$(CLANG))
CLANGXX := $(subst clang,clang++,$(CLANG))

PROTOC := protoc
PKGCONFIG := pkg-config
PROTOBUF_CFLAGS := $(shell $(PKGCONFIG) --cflags protobuf)

CKB_C_STDLIB := $(cur_dir)/deps/ckb-c-stdlib
LIBPROTOBUF_MUTATOR := $(cur_dir)/deps/libprotobuf-mutator

SOURCES := $(shell find mock_syscalls -type f -name "*.h" -o -name "*.cc" | grep -v \.pb\.)

gen-proto:
	cd mock_syscalls && $(PROTOC) --cpp_out=. traces.proto

fmt:
	$(CLANG_FORMAT) --style='{BasedOnStyle: google, SortIncludes: false}' -i \
		$(SOURCES)

flatten: gen-proto
	cargo run --manifest-path tools/flattener/Cargo.toml -- \
		-i mock_syscalls/fuzzing_syscalls_all_in_one.h \
		-o amalgamated/fuzzing_syscalls_all_in_one.h \
		mock_syscalls $(CKB_C_STDLIB)

test-build: flatten gen-proto
	$(CLANGXX) -g -Wall -O3 -c test/test.cc -o test.o \
		$(PROTOBUF_CFLAGS) \
		-I mock_syscalls -I $(CKB_C_STDLIB) -I $(LIBPROTOBUF_MUTATOR)
	$(CLANGXX) -g -Wall -O3 -c test/test.cc -o test_amalgamated.o \
		$(PROTOBUF_CFLAGS) \
		-I amalgamated -I $(CKB_C_STDLIB) -I $(LIBPROTOBUF_MUTATOR)

.PHONY: flatten fmt gen-proto test-build
