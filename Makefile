cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)

CLANG := $(shell $(TOP)/scripts/find_clang)
CLANG_FORMAT := $(subst clang,clang-format,$(CLANG))
CLANGXX := $(subst clang,clang++,$(CLANG))

CKB_C_STDLIB := $(cur_dir)/deps/ckb-c-stdlib
LIBPROTOBUF_MUTATOR := $(cur_dir)/deps/libprotobuf-mutator

fmt:
	$(CLANG_FORMAT) --style='{BasedOnStyle: google, SortIncludes: false}' -i \
		mock_syscalls/*.h mock_syscalls/*.cc

flatten:
	cargo run --manifest-path tools/flattener/Cargo.toml -- \
		-i mock_syscalls/fuzzing_syscalls_all_in_one.h \
		-o amalgamated/fuzzing_syscalls_all_in_one.h \
		mock_syscalls $(CKB_C_STDLIB)

test-build:
	$(CLANGXX) -g -Wall -O3 -c test/test.cc -o test.o \
		-I mock_syscalls -I $(CKB_C_STDLIB) -I $(LIBPROTOBUF_MUTATOR)
	$(CLANGXX) -g -Wall -O3 -c test/test.cc -o test_amalgamated.o \
		-I amalgamated -I $(CKB_C_STDLIB) -I $(LIBPROTOBUF_MUTATOR)

.PHONY: flatten fmt test-build
