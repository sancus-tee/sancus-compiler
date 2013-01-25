include(FindPackageHandleStandardArgs)

find_program(SPM_COMPILER spm-compiler)
find_program(SPM_LINKER spm-linker)
find_package_handle_standard_args("SpmCompiler (compiler)" DEFAULT_MSG SPM_COMPILER)
find_package_handle_standard_args("SpmCompiler (linker)" DEFAULT_MSG SPM_LINKER)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR})
find_package(MSPGCC)

set(CMAKE_C_COMPILER ${SPM_COMPILER})
set(CMAKE_C_LINK_EXECUTABLE "${SPM_LINKER} <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>")

macro(add_spm)
    cmake_parse_arguments(ARG "" "ID;STACK_SIZE" "" ${ARGN})

    list(LENGTH ARG_UNPARSED_ARGUMENTS _LEN)
    if (NOT _LEN EQUAL 2)
        message(FATAL_ERROR "Usage: add_spm(<name> [ID id] [STACK_SIZE size] source")
    endif ()

    list(GET ARG_UNPARSED_ARGUMENTS 0 NAME)
    list(GET ARG_UNPARSED_ARGUMENTS 1 SRC)

    if (NOT ARG_ID)
        set(ARG_ID ${NAME})
    endif ()
    if (ARG_STACK_SIZE)
        set(SIZE_FLAG "--spm-stack-size ${ARG_STACK_SIZE}")
    endif ()

    add_library(${NAME} OBJECT ${SRC})
    set_target_properties(${NAME} PROPERTIES
                          COMPILE_FLAGS "--spm-id ${ARG_ID} ${SIZE_FLAG}")
endmacro()

macro(add_spm_executable)
    cmake_parse_arguments(ARG "" "ROM_SIZE;RAM_SIZE" "SPMS" ${ARGN})

    list(LENGTH ARG_UNPARSED_ARGUMENTS _LEN)
    if (_LEN LESS 2)
        message("Unparsed: ${ARG_UNPARSED_ARGUMENTS}")
        message(FATAL_ERROR "Usage: add_spm_executable(<name> [SPMS spm...] source...")
    endif ()

    if (ARG_ROM_SIZE)
        set(ROM_FLAG "--rom-size ${ARG_ROM_SIZE}")
    endif ()
    if (ARG_RAM_SIZE)
        set(RAM_FLAG "--ram-size ${ARG_RAM_SIZE}")
    endif ()

    list(GET ARG_UNPARSED_ARGUMENTS 0 NAME)
    list(REMOVE_AT ARG_UNPARSED_ARGUMENTS 0)
    set(SRC ${ARG_UNPARSED_ARGUMENTS})

    foreach (SPM ${ARG_SPMS})
        set(SPM_OBJS ${SPM_OBJS} $<TARGET_OBJECTS:${SPM}>)
    endforeach ()

    add_executable(${NAME} ${SRC} ${SPM_OBJS})
    set_target_properties(${NAME} PROPERTIES
                          LINK_FLAGS "${ROM_FLAG} ${RAM_FLAG}")
endmacro()
