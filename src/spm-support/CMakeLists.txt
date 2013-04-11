find_package(MSPGCC REQUIRED)
include(UseMSPGCC)

enable_language(ASM)

set(SRC_SPM
    spm-support.c
)

set(SRC_HOST
    unprotected_entry.s
)

add_library(spm-support STATIC ${SRC_SPM})
add_library(spm-host-support STATIC ${SRC_HOST})

install(TARGETS spm-support
        ARCHIVE DESTINATION ${MSPGCC_LIB_DIR})
install(TARGETS spm-host-support
        ARCHIVE DESTINATION ${MSPGCC_LIB_DIR})
install(FILES spm-support.h
        DESTINATION ${MSPGCC_INCLUDE_DIR})
