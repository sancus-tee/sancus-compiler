include(CompilerConfig)
include(LLVMConfig)

set(SRC
    SancusModuleCreator.cpp
    FunctionCcInfo.cpp
    SancusModuleInfo.cpp
    AnnotationParser.cpp
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_llvm_library(SancusModuleCreator MODULE ${SRC})
