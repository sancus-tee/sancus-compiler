include(CompilerConfig)

set(SRC
    hmac.cpp
    spongent.cpp
)

add_definitions(-D_SPONGENT128128008_)
add_library(hmac-spongent SHARED ${SRC})

install(TARGETS hmac-spongent LIBRARY DESTINATION ${INSTALL_DATA_PATH})
