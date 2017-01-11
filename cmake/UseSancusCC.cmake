include(PythonConfig)

set(CMAKE_C_COMPILER ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/drivers/compiler.py --opt-plugin $<TARGET_FILE:SancusModuleCreator>)
