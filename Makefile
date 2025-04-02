cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

CKB_C_STDLIB := $(cur_dir)/deps/ckb-c-stdlib

all: fmt flatten

fmt:
	clang-format-18 --style='{BasedOnStyle: google, SortIncludes: false}' -i \
		mock_syscalls/*.h mock_syscalls/*.cc

flatten:
	cargo run --manifest-path tools/flattener/Cargo.toml -- \
		-i mock_syscalls/fuzzing_syscalls_all_in_one.h \
		-o amalgamated/fuzzing_syscalls_all_in_one.h \
		mock_syscalls $(CKB_C_STDLIB)

.PHONY: fmt
