find_package(PythonInterp 3.0.0 REQUIRED)

function(find_python_module mod)
    execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import ${mod}"
                    RESULT_VARIABLE res
                    OUTPUT_QUIET
                    ERROR_QUIET)
    if (NOT res EQUAL 0)
        message(FATAL_ERROR "Python module ${mod} not found. Maybe run 'pip install ${mod}'")
    endif ()
endfunction(find_python_module)
