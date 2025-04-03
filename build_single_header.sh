#!/bin/sh

set -ex

git clone https://github.com/xxuejie/ckb-script-fuzzing-toolkit
cd ckb-script-fuzzing-toolkit

if [ -n "$1" ]
then
  git checkout $1
fi

git clone https://github.com/nervosnetwork/ckb-c-stdlib deps/ckb-c-stdlib
cd deps/ckb-c-stdlib
git checkout 7245b6268ef623f204501dc2beb6b3ae7d7b3cf4
cd ../..

make flatten

cd ..

cp ckb-script-fuzzing-toolkit/amalgamated/fuzzing_syscalls_all_in_one.h ./
rm -rf ckb-script-fuzzing-toolkit
