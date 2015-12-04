find_package(MSPGCC REQUIRED)
include(AddObject)

include(UseMSPGCC)
add_object(sm_entry.o sm_entry.s)
add_object(sm_exit.o sm_exit.s)
add_object(sm_verify.o sm_verify.s)

include(UseSancusCC)
set(EXTRA_FLAGS -I${CMAKE_SOURCE_DIR}/src/sancus_support)
add_object(sm_output.o sm_output.c ${EXTRA_FLAGS})
add_object(sm_input.o sm_input.c ${EXTRA_FLAGS})
add_object(sm_set_key.o sm_set_key.c ${EXTRA_FLAGS})

set(STUBS
    ${CMAKE_CURRENT_BINARY_DIR}/sm_entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_exit.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_verify.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_output.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_input.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_set_key.o
)

install(FILES ${STUBS}
        DESTINATION ${INSTALL_BASE_DIR})
