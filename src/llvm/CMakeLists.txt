include(CompilerConfig)
include(LLVMConfig)

set(SRC
    SpmCreator.cpp
    FunctionCcInfo.cpp
    SpmInfo.cpp
    AnnotationParser.cpp
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_llvm_loadable_module(SpmCreator ${SRC})
