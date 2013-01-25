include(FindPackageHandleStandardArgs)

find_program(MSPGCC_EXECUTABLE msp430-gcc)
find_package_handle_standard_args(MSPGCC DEFAULT_MSG MSPGCC_EXECUTABLE)

get_filename_component(TMP ${MSPGCC_EXECUTABLE} PATH)
get_filename_component(MSPGCC_BASE_DIR ${TMP}/../msp430 ABSOLUTE)
set(TMP)
set(MSPGCC_LIB_DIR ${MSPGCC_BASE_DIR}/lib)
set(MSPGCC_INCLUDE_DIR ${MSPGCC_BASE_DIR}/include)

if (EXISTS ${MSPGCC_BASE_DIR} AND
    EXISTS ${MSPGCC_LIB_DIR} AND
    EXISTS ${MSPGCC_INCLUDE_DIR})
    message(STATUS "Found MSPGCC installation directory: ${MSPGCC_BASE_DIR}")
else ()
    message(FATAL_ERROR "Cannot find MSPGCC installation directory")
endif ()
