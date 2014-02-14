include(CompilerConfig)

set(SRC
    crypto.cpp
    spongent.cpp
)

# add_definitions(-D_SPONGENT088176088_)
add_library(sancus-crypto SHARED ${SRC})

install(TARGETS sancus-crypto LIBRARY DESTINATION ${INSTALL_DATA_PATH})

add_executable(test test.cpp)
target_link_libraries(test sancus-crypto)
