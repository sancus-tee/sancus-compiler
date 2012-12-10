#define DEBUG_TYPE "spm-creator"

#include "SpmUtils.h"

#include <llvm/Constants.h>
#include <llvm/DerivedTypes.h>
#include <llvm/Module.h>
#include <llvm/Pass.h>
#include <llvm/TypeBuilder.h>

#include <llvm/Support/CallSite.h>
#include <llvm/Support/InstIterator.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;

namespace
{

struct SpmCreator : ModulePass
{
    static char ID;

    SpmCreator();

    virtual bool runOnModule(Module& m);
    void handleFunction(Function& f);
    void handleData(GlobalVariable& gv);
    void createEntryAndExit(Module& m);
    void createFunctionTable(Module& m);
    void createStack(Module& m);
    unsigned getFunctionId(Function& f);
    Function* getStub(Function& f);
    bool isInSpm(const GlobalValue& f);

    typedef std::vector<Function*> EntryList;
    EntryList entries;
    typedef std::map<Function*, Function*> StubMap;
    StubMap stubs;

    Type* wordTy;
    PointerType* voidPtrTy;
};

}

char SpmCreator::ID = 0;
static RegisterPass<SpmCreator> SPM("create-spm", "Create SPM");

SpmCreator::SpmCreator() : ModulePass(ID)
{
}

bool SpmCreator::runOnModule(Module& m)
{
    using namespace llvm::types;

    LLVMContext& ctx = m.getContext();
    wordTy = TypeBuilder<i<16>, true>::get(ctx);
    voidPtrTy = TypeBuilder<i<8>*, true>::get(ctx);

    for (GlobalVariable& gv : m.getGlobalList())
        handleData(gv);
    for (Function& f : m.getFunctionList())
        handleFunction(f);

    createEntryAndExit(m);
    createFunctionTable(m);
    createStack(m);

    return true;
}

void SpmCreator::handleFunction(Function& f)
{
    if (!isInSpm(f) || f.isIntrinsic())
        return;

    StringRef origName = f.getName();
    f.setName(SpmUtils::getStubName(origName));
    f.setLinkage(Function::InternalLinkage);
    f.setSection(SpmUtils::getTextSection());

    std::string asmStub = Twine("\t.global " + origName + "\n"
                                "\t.text\n"
                                "\t.align 2\n" +
                                origName + ":\n"
                                "\tpush r6\n"
                                "\tmov #" + Twine(getFunctionId(f)) + ", r6\n"
                                "\tbr #__spm_entry\n\n"
                               ).str();

    f.getParent()->appendModuleInlineAsm(asmStub);

    for (inst_iterator it = inst_begin(f), end = inst_end(f); it != end; ++it)
    {
        CallSite cs(&*it);
        if (!cs)
            continue;

        Function* callee = cs.getCalledFunction();
        assert(callee != nullptr && "Function pointers not supported yet");

        if (isInSpm(*callee) || callee->isIntrinsic())
            continue;

        cs.setCalledFunction(getStub(*callee));
    }
}

void SpmCreator::handleData(GlobalVariable& gv)
{
    if (!isInSpm(gv))
        return;

    gv.setLinkage(GlobalVariable::InternalLinkage);
    gv.setSection(SpmUtils::getDataSection());
}

void SpmCreator::createEntryAndExit(Module& m)
{
    m.appendModuleInlineAsm(SpmUtils::getEntryAsmStub());
    m.appendModuleInlineAsm(SpmUtils::getExitAsmStub());
}

void SpmCreator::createFunctionTable(Module& m)
{
    // struct SpmFunctionInfo
    // {
    //     void* address;
    //     unsigned arg_length;
    //     unsigned ret_regs;
    // };
    Type* funcInfoFields[] = {voidPtrTy, wordTy, wordTy};

    StructType* funcInfoTy = StructType::get(m.getContext(), funcInfoFields,
                                             /*isPacked=*/true);

    // struct SpmFunctionTable
    // {
    //     unsigned num_funcs;
    //     struct SpmFunctionInfo funcs[];
    // };
    ArrayType* funcsTy = ArrayType::get(funcInfoTy, entries.size());
    Type* funcTableFields[] = {wordTy, funcsTy};
    StructType* tableTy = StructType::get(m.getContext(), funcTableFields,
                                          /*isPacked=*/true);

    // create a global spm function table and initialize it
    // initializer for the funcs[] array
    std::vector<Constant*> funcsEls;
    for (Function* f : entries)
    {
        // initializer for the SpmFunctionInfo struct
        FunctionCcInfo ccInfo = SpmUtils::getFunctionCcInfo(f);
        Constant* funcFields[] = {ConstantExpr::getBitCast(f, voidPtrTy),
                                  ConstantInt::get(wordTy, ccInfo.argsLength),
                                  ConstantInt::get(wordTy, ccInfo.retRegsUsage)};
        funcsEls.push_back(ConstantStruct::get(funcInfoTy, funcFields));
    }

    Constant* funcsInit = ConstantArray::get(funcsTy, funcsEls);

    // initializer for the function table
    Constant* funcTableEls[] = {ConstantInt::get(wordTy, entries.size()),
                                funcsInit};
    Constant* funcTableInit = ConstantStruct::get(tableTy, funcTableEls);

    GlobalVariable* table =
        new GlobalVariable(m, tableTy, /*isConstant=*/true,
                           GlobalVariable::InternalLinkage, funcTableInit,
                           SpmUtils::getFunctionTableName());
    table->setSection(SpmUtils::getDataSection());
    table->setAlignment(2);
}

void SpmCreator::createStack(Module& m)
{
    using namespace llvm::types;

    LLVMContext& ctx = m.getContext();
    unsigned stackSize = SpmUtils::getStackSize();

    Type* stackTy = ArrayType::get(TypeBuilder<i<8>, true>::get(ctx),
                                   stackSize);
    Constant* stackInit = ConstantAggregateZero::get(stackTy);
    GlobalVariable* stack = new GlobalVariable(m, stackTy, /*isConstant=*/false,
                                               GlobalVariable::InternalLinkage,
                                               stackInit,
                                               SpmUtils::getStackName());
    stack->setSection(SpmUtils::getDataSection());

    Constant* gepIdx[] = {ConstantInt::get(wordTy, 0),
                          ConstantInt::get(wordTy, stackSize)};
    Constant* spmSpInit = ConstantExpr::getGetElementPtr(stack, gepIdx);
    GlobalVariable* spmSp = new GlobalVariable(m, voidPtrTy,
                                               /*isConstant=*/false,
                                               GlobalVariable::InternalLinkage,
                                               spmSpInit,
                                               SpmUtils::getSpmSpName());
    spmSp->setSection(SpmUtils::getDataSection());

    Constant* unprotectedSpInit = ConstantPointerNull::get(voidPtrTy);
    GlobalVariable* unprotectedSp =
        new GlobalVariable(m, voidPtrTy, /*isConstant=*/false,
                           GlobalVariable::InternalLinkage, unprotectedSpInit,
                           SpmUtils::getUnprotectedSpName());
    unprotectedSp->setSection(SpmUtils::getDataSection());
}

unsigned int SpmCreator::getFunctionId(Function& f)
{
    EntryList::iterator it = std::find(entries.begin(), entries.end(), &f);

    if (it == entries.end())
    {
        entries.push_back(&f);
        return entries.size() - 1;
    }
    else
        return it - entries.begin();
}

Function* SpmCreator::getStub(Function& f)
{
    assert(!isInSpm(f) && "Asking for stub of SPM function");

    StubMap::iterator it = stubs.find(&f);
    if (it != stubs.end())
        return it->second;

    StringRef origName = f.getName();
    std::string stubName = SpmUtils::getStubName(origName);
    Module* m = f.getParent();
    Function* stubDecl = Function::Create(f.getFunctionType(),
                                          Function::ExternalLinkage,
                                          stubName, m);

    FunctionCcInfo ccInfo = SpmUtils::getFunctionCcInfo(&f);

    std::string stub = Twine("\t.align 2\n"
                             "\t.section " + SpmUtils::getTextSection() +
                                ",\"ax\",@progbits\n" +
                             stubName + ":\n"
                             "\tpush r7\n"
                             "\tpush r8\n"
                             "\tpush r9\n"
                             "\tpush r10\n"
                             "\tmov #" + Twine(ccInfo.argsLength) + ", r7\n"
                             "\tmov #" + origName + ", r8\n"
                             "\tmov #" + Twine(ccInfo.argRegsUsage) + ", r9\n"
                             "\tmov #" + Twine(ccInfo.retLength) + ", r10\n"
                             "\tbr #" + SpmUtils::getSpmExitName() + "\n\n"
                            ).str();

    m->appendModuleInlineAsm(stub);

    stubs[&f] = stubDecl;
    return stubDecl;
}

bool SpmCreator::isInSpm(const GlobalValue& gv)
{
    if (gv.isDeclaration())
        return false;

    if (gv.hasUnnamedAddr())
        return false;

    return true;
}
