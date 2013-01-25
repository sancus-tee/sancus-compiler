set(SRC
    FindMSPGCC.cmake
    UseMSPGCC.cmake
    SpmCompilerConfig.cmake
)

install(FILES ${SRC} DESTINATION ${INSTALL_DATA_PATH}/cmake)
