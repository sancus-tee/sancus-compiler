file(RELATIVE_PATH REL_INCLUDES_DIR ${INSTALL_CMAKE_DIR} ${INSTALL_INCLUDES_DIR})
configure_file(Sancus-CompilerConfig.cmake.in Sancus-CompilerConfig.cmake @ONLY)

set(SRC
    FindMSPGCC.cmake
    UseMSPGCC.cmake
    SpmCompilerConfig.cmake
    SancusCrypto.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/Sancus-CompilerConfig.cmake
)

configure_file(SancusCrypto.cmake SancusCrypto.cmake COPYONLY)

export(TARGETS sancus-sm-support sancus-host-support
       NAMESPACE sancus_compiler_
       FILE "${CMAKE_CURRENT_BINARY_DIR}/ExportTargets.cmake")

install(FILES ${SRC} DESTINATION ${INSTALL_CMAKE_DIR})
