find_package(MSPGCC REQUIRED)
include(UseMSPGCC)
include(AddObject)

add_object(spm_entry.o spm_entry.s)
add_object(spm_exit.o spm_exit.s)
add_object(unprotected_entry.o unprotected_entry.s)

set(STUBS
    ${CMAKE_CURRENT_BINARY_DIR}/spm_entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/spm_exit.o
    ${CMAKE_CURRENT_BINARY_DIR}/unprotected_entry.o
)

install(FILES ${STUBS}
        DESTINATION ${INSTALL_DATA_PATH})
