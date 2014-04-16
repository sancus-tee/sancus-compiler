include(CMakeParseArguments)

function(add_macs output)
    cmake_parse_arguments(ARG "" "TARGET;VENDOR_KEY" "" ${ARGN})
    if (NOT TARGET ${ARG_TARGET})
        message(FATAL_ERROR "Given TARGET ${ARG_TARGET} is not a target")
    endif ()

    set(input $<TARGET_FILE:${ARG_TARGET}>)

    add_custom_command(TARGET  ${ARG_TARGET} POST_BUILD
                       COMMAND ${SANCUS_CRYPTO} --key ${ARG_VENDOR_KEY} -o ${output} ${input}
                       COMMENT "Generating MACs into ${output}")
endfunction()
