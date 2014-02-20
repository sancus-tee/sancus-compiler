project(SancusCompiler)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(INSTALL_DATA_PATH share/sancus-compiler)
set(FULL_INSTALL_DATA_PATH ${CMAKE_INSTALL_PREFIX}/${INSTALL_DATA_PATH})

if (NOT SECURITY)
    set(SECURITY 64)
endif ()

add_subdirectory(src)
add_subdirectory(cmake)

set(CPACK_GENERATOR "DEB")

set(CPACK_PACKAGE_NAME "sancus-compiler")
set(CPACK_PACKAGE_VERSION "1.0")
set(CPACK_PACKAGE_CONTACT "Job Noorman <Job.Noorman@cs.kuleuven.be>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sancus compiler")

#set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "all")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "python2.7, gcc-msp430, llvm-sancus")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE
    "http://people.cs.kuleuven.be/~job.noorman/sancus")

include(CPack)
