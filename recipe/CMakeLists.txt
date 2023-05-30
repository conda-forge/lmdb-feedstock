cmake_minimum_required(VERSION 3.0)

project(lmdb LANGUAGES C)

# Options
# =======

option(BUILD_EXECS "Build executables" ON)
option(BUILD_TESTING "Build tests" OFF)

# Version
# =======

# TODO: we currently only support the versioning scheme used by the
# official lmdb repository. A versioning scheme for the ABI could be
# added in the future following libtool's versioning scheme:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/lmdb.h" lmdb_version_defines
     REGEX "#define MDB_VERSION_(MAJOR|MINOR|PATCH)")

foreach(ver ${lmdb_version_defines})
    if(ver MATCHES "#define MDB_VERSION_(MAJOR|MINOR|PATCH)[ \t]+([^ ]+)$")
        set(LMDB_VERSION_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}" CACHE INTERNAL "")
    endif()
endforeach()

set(LMDB_VERSION
    ${LMDB_VERSION_MAJOR}.${LMDB_VERSION_MINOR}.${LMDB_VERSION_PATCH})

message(STATUS "LMDB version: ${LMDB_VERSION}")

# Build shared library
# ====================

add_library(lmdb SHARED mdb.c midl.c)
target_include_directories(
    lmdb INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

set_target_properties(lmdb PROPERTIES
    PUBLIC_HEADER lmdb.h
    VERSION ${LMDB_VERSION}
    OUTPUT_NAME lmdb
)

install(TARGETS lmdb
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Build lmdb utilities (executables)
# ==================================

if(${BUILD_EXECS})
    message(STATUS "Building lmdb utilities (executables)")

    add_executable(mdb_stat mdb_stat.c)
    target_link_libraries(mdb_stat lmdb)

    add_executable(mdb_copy mdb_copy.c)
    target_link_libraries(mdb_copy lmdb)

    add_executable(mdb_dump mdb_dump.c)
    target_link_libraries(mdb_dump lmdb)

    add_executable(mdb_load mdb_load.c)
    target_link_libraries(mdb_load lmdb)
endif()

# Tests
# =====

if(${BUILD_TESTING})
    message(STATUS "Building tests")
    enable_testing()

    add_executable(mtest mtest.c)
    target_link_libraries(mtest lmdb)
    add_test(NAME mtest COMMAND mtest)

    set (NUMBERS 2 3 4 5)
    foreach(i IN LISTS NUMBERS)
        add_executable(mtest${i} mtest${i}.c)
        target_link_libraries(mtest${i} lmdb)
        add_test(NAME mtest${i} COMMAND mtest${i})
    endforeach()
endif()

# Installation
# ============

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(
    LMDB_CMAKECONFIG_INSTALL_DIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
    CACHE STRING
    "Installation directory for cmake config files, relative to ${CMAKE_INSTALL_PREFIX}."
)

install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/lmdb"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# Makes the project importable from the build directory
export(
    EXPORT ${PROJECT_NAME}-targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake"
)

# Configure 'lmdbConfig.cmake' for a build tree
set(LMDB_CONFIG_CODE "####### Expanded from \@lmdb_CONFIG_CODE\@ #######\n")
set(LMDB_CONFIG_CODE "${LMDB_CONFIG_CODE}set(CMAKE_MODULE_PATH \"${CMAKE_CURRENT_SOURCE_DIR}/cmake;\${CMAKE_MODULE_PATH}\")\n")
set(LMDB_CONFIG_CODE "${LMDB_CONFIG_CODE}####### End of expanded section on lmdb_CONFIG_CODE #######\n")

configure_package_config_file(
    ${PROJECT_NAME}Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION ${LMDB_CMAKECONFIG_INSTALL_DIR}
)

# Configure 'lmdbConfig.cmake' for an install tree
configure_package_config_file(
    ${PROJECT_NAME}Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "${LMDB_CMAKECONFIG_INSTALL_DIR}"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/lmdbConfigVersion.cmake"
    VERSION ${LMDB_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
    FILES
    "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION ${LMDB_CMAKECONFIG_INSTALL_DIR}
)

install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    DESTINATION ${LMDB_CMAKECONFIG_INSTALL_DIR}
)
