cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)

CLANG := $(shell $(TOP)/scripts/find_clang)
CLANG_FORMAT := $(subst clang,clang-format,$(CLANG))
CLANGXX := $(subst clang,clang++,$(CLANG))
LLVM_AR := $(subst clang,llvm-ar,$(CLANG))

HFUZZ_CLANGXX := hfuzz-clang++
AFLXX_CLANGXX := afl-clang-fast++

PROTOC := protoc
PKGCONFIG := pkg-config

CKB_C_STDLIB := $(cur_dir)/deps/ckb-c-stdlib
CUSTOM_CFLAGS := -I $(CKB_C_STDLIB) \
	$(shell $(PKGCONFIG) --cflags libprotobuf-mutator) \
	$(shell $(PKGCONFIG) --cflags protobuf)

CFLAGS := $(CUSTOM_CFLAGS) -g -Wall -O3 -I include -I src -I protos

SRCS := $(shell find src -name "*.cc")
HDRS := $(shell find src include -name "*.h")
PROTO_SRCS := protos/traces.pb.cc

all: libfuzzer hfuzz aflxx

libfuzzer: obj/libckb-fuzzing-libfuzzer-protobuf.a
hfuzz: obj/libckb-fuzzing-hfuzz-protobuf.a
aflxx: obj/libckb-fuzzing-aflxx-protobuf.a

obj/libckb-fuzzing-libfuzzer-protobuf.a: obj/libfuzzer/src/interfaces/libfuzzer.o \
	obj/libfuzzer/src/syscalls/protobuf.o obj/libfuzzer/protos/traces.pb.o
obj/libckb-fuzzing-aflxx-protobuf.a: obj/aflxx/src/interfaces/aflxx.o \
	obj/aflxx/src/syscalls/protobuf.o obj/aflxx/protos/traces.pb.o
obj/libckb-fuzzing-hfuzz-protobuf.a: obj/hfuzz/src/interfaces/file.o \
	obj/hfuzz/src/syscalls/protobuf.o obj/hfuzz/protos/traces.pb.o

obj/libfuzzer/%.o: %.cc $(HDRS) $(PROTO_SRCS)
	mkdir -p $(dir $@)
	$(CLANGXX) $(CFLAGS) -c $< -o $@

obj/hfuzz/%.o: %.cc $(HDRS) $(PROTO_SRCS)
	mkdir -p $(dir $@)
	$(HFUZZ_CLANGXX) $(CFLAGS) -c $< -o $@

obj/aflxx/%.o: %.cc $(HDRS) $(PROTO_SRCS)
	mkdir -p $(dir $@)
	$(AFLXX_CLANGXX) $(CFLAGS) -c $< -o $@

obj/%.a:
	mkdir -p $(dir $@)
	$(LLVM_AR) -rc $@ $^

# For simplicity, we are only dealing with traces.pb.cc in this makefile,
# we will just assume traces.pb.h will be generated together with traces.pb.cc
protos/traces.pb.cc: protos/traces.proto
	cd protos && $(PROTOC) --cpp_out=. traces.proto

clean:
	rm -rf obj protos/*.pb.*
	cargo clean --manifest-path tools/flattener/Cargo.toml

fmt:
	$(CLANG_FORMAT) --style='{BasedOnStyle: google, SortIncludes: false}' -i \
		$(SRCS) $(HDRS)

flatten: $(PROTO_SRCS)
	cargo run --manifest-path tools/flattener/Cargo.toml -- \
		-i amalgamated/index.h \
		-o amalgamated/fuzzing_syscalls_all_in_one.h \
		src include protos $(CKB_C_STDLIB)

.PHONY: libfuzzer hfuzz aflxx clean fmt flatten
