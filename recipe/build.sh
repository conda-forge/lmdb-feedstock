#!/bin/bash

cd libraries/liblmdb/

if [[ -z "${AR}" ]]; then
  AR=ar
fi
export DESTDIR=$PREFIX

make CC=$CC AR=$AR
make test
make install
