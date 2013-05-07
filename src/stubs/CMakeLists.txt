find_package(MSPGCC REQUIRED)
include(UseMSPGCC)
include(AddObject)

add_object(sm_entry.o sm_entry.s)
add_object(sm_exit.o sm_exit.s)
add_object(sm_verify.o sm_verify.s)

set(STUBS
    ${CMAKE_CURRENT_BINARY_DIR}/sm_entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_exit.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_verify.o
)

install(FILES ${STUBS}
        DESTINATION ${INSTALL_DATA_PATH})
