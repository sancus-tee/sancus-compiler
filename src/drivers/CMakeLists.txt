include(PythonConfig)
find_python_module(elftools)

configure_file(spm-compiler.in spm-compiler @ONLY)
configure_file(spm-linker.in spm-linker @ONLY)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/spm-compiler ${CMAKE_CURRENT_BINARY_DIR}/spm-linker
        DESTINATION bin)

install(FILES compiler.py linker.py common.py msp430.x memory.x periph.x
        DESTINATION ${INSTALL_DATA_PATH})
