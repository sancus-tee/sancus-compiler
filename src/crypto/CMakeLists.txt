include(CompilerConfig)

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC
    crypto.cpp
    spongent.cpp
)

add_library(sancus-crypto SHARED ${SRC})

install(TARGETS sancus-crypto
        LIBRARY DESTINATION ${INSTALL_BASE_DIR})

set(PY_LIBS
	libsancuscrypt.py
)

install(FILES ${PY_LIBS}  DESTINATION ${INSTALL_PYTHON_LIBS_DIR}/sancus)
