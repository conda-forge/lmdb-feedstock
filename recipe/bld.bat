@echo on

cd libraries/liblmdb/

:: for details on why these values are set, check out the upstream Makefile
:: https://github.com/LMDB/lmdb/blob/mdb.master/libraries/liblmdb/Makefile

set "DESTDIR=%LIBRARY_PREFIX%"
set "SOEXT=.dll"
set "CC=%CC%"

:: disable gcc-style options that MSVC doesn't understand
set "CFLAGS=%CFLAGS%"

:: only build shared lib, don't build programs & docs
set "ILIBS=liblmdb.dll"
set "IPROGS="
set "IDOCS="

make
make install
