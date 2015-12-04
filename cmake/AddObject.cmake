macro(add_object OBJECT FILE)
    get_filename_component(TARGET ${OBJECT} NAME_WE)
    add_custom_command(OUTPUT ${OBJECT}
                       DEPENDS ${FILE}
                       COMMAND ${CMAKE_C_COMPILER} ${CMAKE_CFLAGS} -c ${ARGN} ${CMAKE_CURRENT_SOURCE_DIR}/${FILE} -o ${OBJECT})
    add_custom_target(${TARGET} ALL DEPENDS ${OBJECT})
endmacro()
