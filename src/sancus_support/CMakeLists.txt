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

install(TARGETS sancus-sm-support
        ARCHIVE DESTINATION ${MSPGCC_LIB_DIR})
install(TARGETS sancus-host-support
        ARCHIVE DESTINATION ${MSPGCC_LIB_DIR})
install(FILES sm_support.h
        DESTINATION ${MSPGCC_INCLUDE_DIR}/sancus)
