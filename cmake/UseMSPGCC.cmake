set(CMAKE_C_COMPILER ${MSPGCC_EXECUTABLE})

if(MSP430_GCC_PREFIX STREQUAL msp430-elf)
  set(mcu msp430sancus)
  include_directories (${MSPGCC_BASE_DIR}/../include)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mmcu=${mcu}")
else()
  set(mcu msp430f149)
endif()
