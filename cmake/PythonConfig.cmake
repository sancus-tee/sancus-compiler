find_package(PythonInterp REQUIRED)

function(find_python_module mod)
    execute_process(COMMAND python -c "import ${mod}"
                    RESULT_VARIABLE res
                    OUTPUT_QUIET
                    ERROR_QUIET)
    if (NOT res EQUAL 0)
        message(FATAL_ERROR "Python module ${mod} not found. Maybe run 'pip install ${mod}'")
    endif ()
endfunction(find_python_module)
