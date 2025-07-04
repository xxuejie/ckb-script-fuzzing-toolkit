FROM docker.io/buildpack-deps:noble as builder
MAINTAINER Xuejie Xiao <xxuejie@gmail.com>

RUN apt-get update
RUN apt-get install -y llvm llvm-dev clang clang-format lld git \
  binutils-dev libunwind-dev libblocksruntime-dev \
  protobuf-compiler libprotobuf-dev binutils cmake \
  ninja-build liblzma-dev libz-dev pkg-config autoconf libtool

RUN git clone https://github.com/google/honggfuzz /tmp/honggfuzz && \
  cd /tmp/honggfuzz && \
  git checkout 4cfa62f4fdb56e3027c1cb3aecf04812e786f0fd && \
  make && \
  make install && \
  cd / && \
  rm -rf /tmp/honggfuzz

RUN git clone https://github.com/google/libprotobuf-mutator /tmp/mutator && \
  cd /tmp/mutator && \
  git checkout d780394da371517c2e21190d05414845d0ac1e07 && \
  mkdir build && \
  cd build && \
  cmake .. -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug && \
  ninja && \
  ninja install && \
  cd / && \
  rm -rf /tmp/mutator

RUN git clone https://github.com/AFLplusplus/AFLplusplus /tmp/aflpp && \
  cd /tmp/aflpp && \
  git checkout 5a527046a5b0035a556ddeca2c0ad1c7e68e8f03 && \
  make source-only && \
  make install && \
  cd / && \
  rm -rf /tmp/aflpp

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
  -y --default-toolchain 1.87.0 --target riscv64imac-unknown-none-elf
ENV PATH "${PATH}:/root/.cargo/bin"
RUN rustup toolchain install nightly

RUN cargo install \
  --git https://github.com/xxuejie/ckb-script-fuzzing-toolkit \
  --rev 479052e565ef872fbf60531a1ce2dcf54e83085a \
  ckb-vm-syscall-tracer
RUN cargo install cargo-fuzz
RUN cargo install honggfuzz
RUN cargo install cargo-afl

RUN mkdir /code
WORKDIR /code
