# ckb-script-fuzzing-toolkit

A toolkit for fuzzing CKB scripts. It provides mock version of CKB syscalls so you can compile a contract to native x86_64 or aarch64 environment, where you can enjoy all the tools.

## Usage

2 usage modes are provided.

For traditional C style users, clone the repo and generate protobuf files:

```
$ git clone https://github.com/xxuejie/ckb-script-fuzzing-toolkit
$ cd ckb-script-fuzzing-toolkit
$ make gen-proto
```

All the header / source files you need will be in `mock_syscalls` folders. Depending on the fuzzing engine you use, you need to pick either `file_interface.cc` and `libfuzzer_interface.cc`, then compile it together with other `.cc` files, you will get the library to link against.

For single header file lovers, use the following steps:

```
$ git clone https://github.com/xxuejie/ckb-script-fuzzing-toolkit
$ cd ckb-script-fuzzing-toolkit
$ make flatten
```

Then just copy `amalgamated/fuzzing_syscalls_all_in_one.h` anywhere you like and just get rid of the whole toolkit repo. You will be good to go.

Or you can use our one-liner build script:

```
$ curl -sSf https://raw.githubusercontent.com/xxuejie/ckb-script-fuzzing-toolkit/refs/heads/main/build_single_header.sh | sh
```
