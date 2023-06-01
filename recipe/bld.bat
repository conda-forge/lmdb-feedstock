@echo on

setlocal EnableDelayedExpansion

copy %RECIPE_DIR%\CMakeLists.txt %SRC_DIR%\libraries\liblmdb\CMakeLists.txt
copy %RECIPE_DIR%\lmdbConfig.cmake.in %SRC_DIR%\libraries\liblmdb\lmdbConfig.cmake.in

cd libraries/liblmdb/

:: List all files in the current directory, sorted by name.
dir /s /b /o:gn

:: Make a build folder and change to it.
mkdir build
cd build

cmake -G Ninja ^
    -DCMAKE_INSTALL_PREFIX:PATH="%LIBRARY_PREFIX%" ^
    -DCMAKE_PREFIX_PATH:PATH="%LIBRARY_PREFIX%" ^
    -DCMAKE_BUILD_TYPE:STRING=Release ^
    -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON ^
    -DBUILD_TESTING=OFF ^
    -DBUILD_EXECS=OFF ^
    ..
if %ERRORLEVEL% neq 0 exit 1

cmake --build .
if %ERRORLEVEL% neq 0 exit 1

cmake --install .
if %ERRORLEVEL% neq 0 exit 1
