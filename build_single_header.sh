#!/bin/sh

set -ex

git clone https://github.com/xxuejie/ckb-script-fuzzing-toolkit
cd ckb-script-fuzzing-toolkit

if [ -n "$1" ]
then
  git checkout $1
fi

git submodule update --init

make flatten

cd ..

cp ckb-script-fuzzing-toolkit/amalgamated/fuzzing_syscalls_all_in_one.h ./
rm -rf ckb-script-fuzzing-toolkit
