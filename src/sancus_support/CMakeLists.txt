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

configure_file(sm_support.h sm_support.h)

install(TARGETS sancus-sm-support
        EXPORT ExportTargets
        ARCHIVE DESTINATION ${INSTALL_LIBS_DIR})
install(TARGETS sancus-host-support
        EXPORT ExportTargets
        ARCHIVE DESTINATION ${INSTALL_LIBS_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sm_support.h reactive.h
        DESTINATION "${INSTALL_INCLUDES_DIR}/sancus")
