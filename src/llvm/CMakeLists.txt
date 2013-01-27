include(CompilerConfig)
include(LLVMConfig)

set(SRC
    SpmCreator.cpp
    SpmUtils.cpp
    SpmInfo.cpp
    AnnotationParser.cpp
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_llvm_loadable_module(SpmCreator ${SRC})

configure_file(Config.h.in Config.h)
