project(SancusCompiler)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(INSTALL_DATA_PATH share/sancus-compiler)
set(FULL_INSTALL_DATA_PATH ${CMAKE_INSTALL_PREFIX}/${INSTALL_DATA_PATH})

add_subdirectory(src)
add_subdirectory(cmake)
