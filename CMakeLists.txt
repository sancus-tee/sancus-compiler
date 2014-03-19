project(SancusCompiler)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# set(INSTALL_DATA_PATH share/sancus-compiler)
# set(FULL_INSTALL_DATA_PATH ${CMAKE_INSTALL_PREFIX}/${INSTALL_DATA_PATH})

set(INSTALL_BASE_DIR     "share/sancus-compiler")
set(INSTALL_BINS_DIR     "bin")
set(INSTALL_LIBS_DIR     "${INSTALL_BASE_DIR}/lib")
set(INSTALL_INCLUDES_DIR "${INSTALL_BASE_DIR}/include")
set(INSTALL_CMAKE_DIR    "${INSTALL_BASE_DIR}/cmake")

# convert all the above variables to absolute paths
foreach (type BASE BINS LIBS INCLUDES CMAKE)
    set(var INSTALL_${type}_DIR)
    if (NOT IS_ABSOLUTE "${${var}}")
        set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
    endif ()
endforeach ()

if (NOT SECURITY)
    set(SECURITY 64)
endif ()

add_subdirectory(src)
add_subdirectory(cmake)

install(EXPORT ExportTargets
        NAMESPACE sancus_compiler_
        DESTINATION ${INSTALL_CMAKE_DIR})

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
