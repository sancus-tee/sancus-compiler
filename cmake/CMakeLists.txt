file(RELATIVE_PATH REL_INCLUDES_DIR ${INSTALL_CMAKE_DIR} ${INSTALL_INCLUDES_DIR})
configure_file(Sancus-CompilerConfig.cmake.in Sancus-CompilerConfig.cmake @ONLY)

set(SRC
    FindMSPGCC.cmake
    UseMSPGCC.cmake
    SpmCompilerConfig.cmake
    UseSancus-Compiler.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/Sancus-CompilerConfig.cmake
)

install(FILES ${SRC} DESTINATION ${INSTALL_CMAKE_DIR})
