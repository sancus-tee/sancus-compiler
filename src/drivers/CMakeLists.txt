include(PythonConfig)
find_python_module(elftools)

configure_file(config.py.in ${CMAKE_CURRENT_SOURCE_DIR}/config.py @ONLY)
configure_file(sancus-cc.in sancus-cc @ONLY)
configure_file(sancus-ld.in sancus-ld @ONLY)
configure_file(sancus-crypto.in sancus-crypto @ONLY)

set(PROGS
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-cc
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-ld
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-crypto
)

install(PROGRAMS ${PROGS} DESTINATION bin)

set(FILES
    config.py
    compiler.py
    linker.py
    crypto.py
    common.py
    msp430.x
    memory.x
    periph.x
    sancus.ld
)

install(FILES ${FILES} DESTINATION ${INSTALL_DATA_PATH})
