#!/bin/bash

set -ex

cd libraries/liblmdb/

if [[ -z "${AR}" ]]; then
  AR=ar
fi
export DESTDIR=$PREFIX

make CC=$CC AR=$AR
if [[ "${CONDA_BUILD_CROSS_COMPILATION:-0}" == "0" ]]; then
  make test
fi
make install

# delete static library
rm $PREFIX/lib/liblmdb.a
