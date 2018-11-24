#!/bin/bash

cd libraries/liblmdb/

if [[ -z "${AR}" ]]; then
  AR=ar
fi

make CC=$CC AR=$AR prefix=$PREFIX
make test
make install
