find_package(MSPGCC REQUIRED)
include(UseMSPGCC)

enable_language(ASM)

set(SRC_SM
    sm_support.c
)

set(SRC_HOST
    unprotected_entry.s
)

add_library(sancus-sm-support STATIC ${SRC_SM})
add_library(sancus-host-support STATIC ${SRC_HOST})

set(INSTALL_LIB_PATH     ${INSTALL_DATA_PATH}/lib)
set(INSTALL_INCLUDE_PATH ${INSTALL_DATA_PATH}/include/sancus)

install(TARGETS sancus-sm-support
        ARCHIVE DESTINATION ${INSTALL_LIB_PATH})
install(TARGETS sancus-host-support
        ARCHIVE DESTINATION ${INSTALL_LIB_PATH})
install(FILES sm_support.h
        DESTINATION ${INSTALL_INCLUDE_PATH})
