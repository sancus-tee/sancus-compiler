find_package(MSPGCC)
include(UseMSPGCC)

set(SRC
    spm-support.c
)

add_library(spm-support STATIC ${SRC})

install(TARGETS spm-support
        ARCHIVE DESTINATION ${MSPGCC_LIB_DIR})
install(FILES spm-support.h
        DESTINATION ${MSPGCC_INCLUDE_DIR})
