include(PythonConfig)
find_python_module(elftools)

configure_file(spm-compiler.in spm-compiler @ONLY)
configure_file(spm-linker.in spm-linker @ONLY)
configure_file(spm-hmac.in spm-hmac @ONLY)

set(PROGS
    ${CMAKE_CURRENT_BINARY_DIR}/spm-compiler
    ${CMAKE_CURRENT_BINARY_DIR}/spm-linker
    ${CMAKE_CURRENT_BINARY_DIR}/spm-hmac
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
)

install(FILES ${FILES} DESTINATION ${INSTALL_DATA_PATH})
