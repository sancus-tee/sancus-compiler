#define DEBUG_TYPE "spm-creator"

#include "Config.h"

#include "SpmUtils.h"

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <sstream>

using namespace llvm;

static cl::opt<std::string> SpmId("spm-id",
                                  cl::desc("ID for the SPM"),
                                  cl::Required);

static cl::opt<unsigned> StackSize("spm-stack-size",
                                   cl::desc("Stack size for the SPM"),
                                   cl::Optional,
                                   cl::init(256));

std::string SpmUtils::getTextSection()
{
    return ".spm." + SpmId + ".text";
}

std::string SpmUtils::getEntrySection()
{
    return ".spm." + SpmId + ".text.entry";
}

std::string SpmUtils::getDataSection()
{
    return ".spm." + SpmId + ".data";
}

std::string SpmUtils::getStubName(const std::string& origName)
{
    return "__spm_" + SpmId + "_" + origName;
}

std::string SpmUtils::getFunctionTableName()
{
    return "__spm_table";
}

std::string SpmUtils::getStackName()
{
    return "__spm_stack";
}

unsigned SpmUtils::getStackSize()
{
    return StackSize;
}

std::string SpmUtils::getSpmSpName()
{
    return "__spm_sp";
}

std::string SpmUtils::getUnprotectedSpName()
{
    return "__unprotected_sp";
}

std::string SpmUtils::getSpmExitName()
{
    return "__spm_exit";
}

std::string SpmUtils::getEntryAsmStub()
{
    std::stringstream asmStub;
    asmStub << "\t.section " << getEntrySection() << ",\"ax\",@progbits\n"
            << getContentsAsString(SPM_ENTRY_FILE);
    return asmStub.str();
}

std::string SpmUtils::getExitAsmStub()
{
    std::stringstream asmStub;
    asmStub << "\t.section " << getTextSection() << ",\"ax\",@progbits\n"
            << getContentsAsString(SPM_EXIT_FILE);
    return asmStub.str();
}

FunctionCcInfo SpmUtils::getFunctionCcInfo(Function* f)
{
    FunctionCcInfo ret = {0, 0, 0, 0};
    Module* m = f->getParent();

    unsigned argRegsLeft = 4;

    for (Argument& arg : f->getArgumentList())
    {
        Type* argTy = arg.getType();

        if (arg.hasStructRetAttr())
        {
            assert(argRegsLeft == 4 && "sret not first argument?");
            ret.retLength =
                getTypeSize(cast<PointerType>(argTy)->getElementType(), m);
            argRegsLeft--;
            continue;
        }

        if (argTy->isPointerTy() && arg.hasByValAttr())
            argTy = cast<PointerType>(argTy)->getElementType();

        unsigned argSize = getTypeSize(argTy, m);

        if (argSize % 2 == 1)
            ++argSize;

        assert(argSize != 0 && "Unsized argument?");

        if (argRegsLeft == 0 || argTy->isStructTy())
        {
            ret.argsLength += argSize;
            continue;
        }

        // at this point we're with an integral argument and we're sure that
        // argSize is a multiple of 2. do some integrity checks
        assert(argSize != 6 && argSize <= 8 && "Impossible argument size");

        if (2 * argRegsLeft >= argSize)
            argRegsLeft -= argSize / 2;
        else
            ret.argsLength += argSize;
    }

    switch (argRegsLeft)
    {
        case 0:
            ret.argRegsUsage = 0x1;
            break;

        case 1:
            ret.argRegsUsage = 0x2;
            break;

        case 2:
            ret.argRegsUsage = 0x4;
            break;

        case 3:
            ret.argRegsUsage = 0x8;
            break;

        case 4:
            ret.argRegsUsage = 0x0;
            break;

        default:
            llvm_unreachable("Impossible number of registers used");
    }

    Type* retTy = f->getReturnType();

    if (!retTy->isVoidTy())
    {
        switch (getTypeSize(retTy, m))
        {
            case 8:
                ret.retRegsUsage = 0x1;
                break;

            case 4:
                ret.retRegsUsage = 0x2;
                break;

            case 2:
            case 1:
                ret.retRegsUsage = 0x4;
                break;

            default:
                llvm_unreachable("Invalid return type size");
        }
    }

    return ret;
}

unsigned SpmUtils::getTypeSize(Type* type, const Module* m)
{
    return DataLayout(m).getTypeStoreSize(type);
}

std::string SpmUtils::getContentsAsString(const char* fileName)
{
    std::ifstream file(fileName);
    assert(file.is_open());
    std::stringstream stream;
    stream << file.rdbuf();
    return stream.str();
}
