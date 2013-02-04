set(GCC_MIN_VERSION "4.7.0")
set(CLANG_MIN_VERSION "3.0")

macro(get_compiler_version)
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpversion
                    OUTPUT_VARIABLE COMPILER_VERSION)
endmacro()

# check compiler version. needed since I want to use C++11 features :-)
if (CMAKE_COMPILER_IS_GNUCXX)
    get_compiler_version()

    if (COMPILER_VERSION VERSION_LESS ${GCC_MIN_VERSION})
        message(FATAL_ERROR "GCC version >= ${GCC_MIN_VERSION} required\n"
                            "If you are using GCC version >= 4.6.0 and cannot install ${GCC_MIN_VERSION}, "
                            "you can switch to the gcc-4.6 branch: 'git checkout -b gcc-4.6 origin/gcc-4.6'")
    endif()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    get_compiler_version()

    if (COMPILER_VERSION VERSION_LESS ${CLANG_MIN_VERSION})
        message(FATAL_ERROR "Clang version >= ${CLANG_MIN_VERSION} required")
    endif()

    message(WARNING "This project has not been tested when compiled using Clang")
else ()
    message(FATAL_ERROR "Only GCC and Clang are supported")
endif ()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -fno-rtti -std=c++11")

