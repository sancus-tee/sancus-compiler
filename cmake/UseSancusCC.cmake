include(PythonConfig)

get_property(OPT_PLUGIN TARGET SancusModuleCreator PROPERTY LOCATION)
set(CMAKE_C_COMPILER ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/drivers/compiler.py --opt-plugin ${OPT_PLUGIN})
