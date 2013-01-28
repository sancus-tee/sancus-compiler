include(FindPackageHandleStandardArgs)

find_program(MSPGCC_EXECUTABLE msp430-gcc)

get_filename_component(TMP ${MSPGCC_EXECUTABLE} PATH)
get_filename_component(MSPGCC_BASE_DIR ${TMP}/../msp430 ABSOLUTE)
set(TMP)
set(MSPGCC_LIB_DIR ${MSPGCC_BASE_DIR}/lib)
set(MSPGCC_INCLUDE_DIR ${MSPGCC_BASE_DIR}/include)

if (NOT EXISTS ${MSPGCC_BASE_DIR} OR
    NOT EXISTS ${MSPGCC_LIB_DIR} OR
    NOT EXISTS ${MSPGCC_INCLUDE_DIR})
    set(MSPGCC_BASE_DIR)
endif ()

find_package_handle_standard_args(MSPGCC DEFAULT_MSG MSPGCC_EXECUTABLE MSPGCC_BASE_DIR)
