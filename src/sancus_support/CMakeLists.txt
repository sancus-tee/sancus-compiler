find_package(MSPGCC REQUIRED)
include(UseMSPGCC)

enable_language(ASM)

set(SRC_SM
    sm_support.c
)

set(SRC_HOST
    unprotected_entry.s
)

set_source_files_properties(unprotected_entry.s 
                            PROPERTIES 
                            COMPILE_FLAGS "-mmcu=${mcu}")

add_library(sancus-sm-support STATIC ${SRC_SM})
add_library(sancus-host-support STATIC ${SRC_HOST})

configure_file(config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

install(TARGETS sancus-sm-support
        EXPORT ExportTargets
        ARCHIVE DESTINATION ${INSTALL_LIBS_DIR})
install(TARGETS sancus-host-support
        EXPORT ExportTargets
        ARCHIVE DESTINATION ${INSTALL_LIBS_DIR})
install(FILES sm_support.h reactive.h config.h
        DESTINATION "${INSTALL_INCLUDES_DIR}/sancus")
