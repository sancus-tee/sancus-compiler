set(MCU msp430f149)
set(CMAKE_C_COMPILER ${MSPGCC_EXECUTABLE})
include_directories (${MSPGCC_BASE_DIR}/../include)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mmcu=${MCU}")
