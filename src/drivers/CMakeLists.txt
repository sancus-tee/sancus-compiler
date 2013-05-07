include(PythonConfig)
find_python_module(elftools)

configure_file(sancus-cc.in sancus-cc @ONLY)
configure_file(sancus-ld.in sancus-ld @ONLY)
configure_file(sancus-hmac.in sancus-hmac @ONLY)

set(PROGS
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-cc
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-ld
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-hmac
)

install(PROGRAMS ${PROGS} DESTINATION bin)

set(FILES
    compiler.py
    linker.py
    hmac.py
    common.py
    msp430.x
    memory.x
    periph.x
    sancus.ld
)

install(FILES ${FILES} DESTINATION ${INSTALL_DATA_PATH})
