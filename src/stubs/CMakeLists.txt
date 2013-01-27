find_package(MSPGCC)
include(UseMSPGCC)
include(AddObject)

add_object(entry.o entry.s)
add_object(exit.o exit.s)

set(STUBS
    ${CMAKE_CURRENT_BINARY_DIR}/entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/exit.o
)

install(FILES ${STUBS}
        DESTINATION ${INSTALL_DATA_PATH})
