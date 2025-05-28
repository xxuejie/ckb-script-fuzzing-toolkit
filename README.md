# ckb-script-fuzzing-toolkit

A toolkit for fuzzing CKB scripts. It provides mock version of CKB syscalls so you can compile a contract to native x86_64 or aarch64 environment, where you can enjoy all the tools.

## Usage

2 usage modes are provided.

For traditional C style users, clone the repo and generate protobuf files:

```
$ git clone https://github.com/xxuejie/ckb-script-fuzzing-toolkit
$ cd ckb-script-fuzzing-toolkit
$ make
```

However, since fuzzing objects might require special compilers for some fuzzing engines, it might be easier to compile in docker where all deps are already installed:

```
$ docker run --rm -v `pwd`:/code docker.io/xxuejie/ckb-script-fuzzing-toolkit:20250410 make
```

There will be a series of archives created in `obj` folder for you to use.

For single header file lovers, you can use our one-liner build script:

```
$ curl -sSf https://raw.githubusercontent.com/xxuejie/ckb-script-fuzzing-toolkit/refs/heads/main/build_single_header.sh | sh
```

It will generate a siingle `fuzzing_syscalls_all_in_one.h` header file containing everything for ease of integration.
