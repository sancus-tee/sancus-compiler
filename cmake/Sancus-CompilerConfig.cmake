include(FindPackageHandleStandardArgs)

set(SANCUS_BASE "${CMAKE_CURRENT_LIST_DIR}/..")
get_filename_component(SANCUS_BASE ${SANCUS_BASE} ABSOLUTE)
set(SANCUS_INCLUDES "${SANCUS_BASE}/include")
set(SANCUS_MODULE_LIBS "${SANCUS_BASE}/lib/libsancus-sm-support.a")
set(SANCUS_HOST_LIBS "${SANCUS_BASE}/lib/libsancus-host-support.a")

mark_as_advanced(SANCUS_BASE SANCUS_INCLUDES
                 SANCUS_MODULE_LIBS SANCUS_HOST_LIBS)
find_package_handle_standard_args(Sancus-Compiler DEFAULT_MSG
                                  SANCUS_BASE SANCUS_INCLUDES
                                  SANCUS_MODULE_LIBS SANCUS_HOST_LIBS)
