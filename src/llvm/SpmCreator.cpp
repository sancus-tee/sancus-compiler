#define DEBUG_TYPE "spm-creator"

#include "SpmUtils.h"
#include "SpmInfo.h"
#include "AnnotationParser.h"

#include <llvm/Pass.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/TypeBuilder.h>

#include <llvm/Support/CallSite.h>
#include <llvm/Support/InstIterator.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Debug.h>

using namespace llvm;

namespace
{

struct SpmCreator : ModulePass
{
    static char ID;

    SpmCreator();

    virtual void getAnalysisUsage(AnalysisUsage& au) const;
    virtual bool runOnModule(Module& m);

    void handleFunction(Function& f);
    void handleData(GlobalVariable& gv);
    void createFunctionTable(Module& m);
    void createStack(Module& m, const SpmInfo& info);
    unsigned getFunctionId(Function& f);
    Function* getStub(Function& caller, Function& callee);
    bool isInSpm(const GlobalValue& f);
    SpmInfo getSpmInfo(const GlobalValue* gv);

    typedef std::map<const GlobalValue*, SpmInfo> InfoMap;
    InfoMap spmInfo;

    typedef std::vector<Function*> EntryList;
    EntryList entries;
    typedef std::map<std::pair<Function*, Function*>, Function*> StubMap;
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

void SpmCreator::getAnalysisUsage(AnalysisUsage& au) const
{
    au.addRequired<AnnotationParser>();
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

    createFunctionTable(m);

    return true;
}

void SpmCreator::handleFunction(Function& f)
{
    if (f.isIntrinsic())
        return;

    SpmInfo info = getSpmInfo(&f);
    if (info.isInSpm)
    {
        f.setSection(info.getTextSection());
        createStack(*f.getParent(), info);
    }
    if (info.isEntry)
        entries.push_back(&f);

//     StringRef origName = f.getName();
//     f.setName(SpmUtils::getStubName(origName));
//     f.setLinkage(Function::InternalLinkage);
//     f.setSection(SpmUtils::getTextSection());
// 
//     std::string asmStub = Twine("\t.global " + origName + "\n"
//                                 "\t.text\n"
//                                 "\t.align 2\n" +
//                                 origName + ":\n"
//                                 "\tpush r6\n"
//                                 "\tmov #" + Twine(getFunctionId(f)) + ", r6\n"
//                                 "\tbr #__spm_entry\n\n"
//                                ).str();
// 
//     f.getParent()->appendModuleInlineAsm(asmStub);

    for (inst_iterator it = inst_begin(f), end = inst_end(f); it != end; ++it)
    {
        CallSite cs(&*it);
        if (!cs)
            continue;

        Function* callee = cs.getCalledFunction();
        assert(callee != nullptr && "Function pointers not supported yet");

        cs.setCalledFunction(getStub(f, *callee));
    }
}

void SpmCreator::handleData(GlobalVariable& gv)
{
    SpmInfo info = getSpmInfo(&gv);
    if (!info.isInSpm)
        return;

    gv.setSection(info.getDataSection());
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

    // create a global spm function table for every spm and initialize it
    // initializers for the funcs[] array. map from section name to initializer
    std::map<std::string, std::vector<Constant*>> funcsEls;
    for (Function* f : entries)
    {
        SpmInfo info = getSpmInfo(f);
        assert(info.isEntry && "Asking function table for non-entry");

        // initializer for the SpmFunctionInfo struct
        FunctionCcInfo ccInfo = SpmUtils::getFunctionCcInfo(f);
        if (ccInfo.argsLength != 0 || ccInfo.retLength != 0)
        {
            errs() << "Warning: Passing arguments on the stack between SPMs "
                      "will not work";
        }

        Constant* funcFields[] = {ConstantExpr::getBitCast(f, voidPtrTy),
                                  ConstantInt::get(wordTy, ccInfo.argsLength),
                                  ConstantInt::get(wordTy, ccInfo.retRegsUsage)};
        funcsEls[info.getTableSection()]
            .push_back(ConstantStruct::get(funcInfoTy, funcFields));
    }

    for (const auto& it : funcsEls)
    {
        // struct SpmFunctionInfo funcs[];
        ArrayType* funcsTy = ArrayType::get(funcInfoTy, it.second.size());
        Constant* funcsInit = ConstantArray::get(funcsTy, it.second);

        GlobalVariable* table =
            new GlobalVariable(m, funcsTy, /*isConstant=*/true,
                               GlobalVariable::InternalLinkage, funcsInit);
        table->setSection(it.first);
        table->setAlignment(2);
    }
}

void SpmCreator::createStack(Module& m, const SpmInfo& info)
{
    using namespace llvm::types;

    if (m.getGlobalVariable(info.getStackName()) != nullptr)
        return;

    LLVMContext& ctx = m.getContext();
    unsigned stackSize = SpmUtils::getStackSize();

    Type* stackTy = ArrayType::get(TypeBuilder<i<8>, true>::get(ctx),
                                   stackSize);
    Constant* stackInit = ConstantAggregateZero::get(stackTy);
    GlobalVariable* stack = new GlobalVariable(m, stackTy, /*isConstant=*/false,
                                               GlobalVariable::WeakAnyLinkage,
                                               stackInit,
                                               info.getStackName());
    stack->setSection(info.getDataSection());

    Constant* gepIdx[] = {ConstantInt::get(wordTy, 0),
                          ConstantInt::get(wordTy, stackSize)};
    Constant* spmSpInit = ConstantExpr::getGetElementPtr(stack, gepIdx);
    GlobalVariable* spmSp = new GlobalVariable(m, voidPtrTy,
                                               /*isConstant=*/false,
                                               GlobalVariable::WeakAnyLinkage,
                                               spmSpInit,
                                               info.getSpName());
    spmSp->setSection(info.getDataSection());
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

Function* SpmCreator::getStub(Function& caller, Function& callee)
{
    Module* m = caller.getParent();

    auto pair = std::make_pair(&caller, &callee);
    StubMap::iterator it = stubs.find(pair);
    if (it != stubs.end())
        return it->second;

    Function* stub = nullptr;
    std::string stubAsm;

    SpmInfo callerInfo = getSpmInfo(&caller);
    SpmInfo calleeInfo = getSpmInfo(&callee);

    if (callerInfo.name == calleeInfo.name) // call within SPM/unprotected
        stub = &callee;
    else if (callerInfo.name.empty()) // call unprotected -> SPM
    {
        assert(calleeInfo.isEntry && "Calling non-entry function");
        std::string sectionName = callerInfo.getTextSection();
        std::string stubName = callerInfo.getCalleeStubName(callee.getName());
        std::string idxName = calleeInfo.getIndexName(callee.getName());
        std::string brName = calleeInfo.getEntryName();

        stubAsm = Twine("\t.align 2\n"
                        "\t.section " + sectionName + ",\"ax\",@progbits\n"
                        "\t.weak " + stubName + + "\n" +
                        stubName + ":\n"
                        "\tpush r6\n"
                        "\tpush r7\n"
                        "\tmov #" + idxName + ", r6\n"
                        "\tmov #1f, r7\n"
                        "\tmov r1, &__unprotected_sp\n"
                        "\tbr #" + brName + "\n"
                        "1:\n"
                        "\tmov &__unprotected_sp, r1\n"
                        "\tpop r7\n"
                        "\tpop r6\n"
                        "\tret"
                       ).str();

        stub = Function::Create(callee.getFunctionType(),
                                Function::ExternalLinkage, stubName, m);
    }
    else // call SPM -> SPM/unprotected
    {
        FunctionCcInfo ccInfo = SpmUtils::getFunctionCcInfo(&callee);
        std::string sectionName = callerInfo.getTextSection();
        std::string stubName = callerInfo.getCalleeStubName(callee.getName());
        Twine regsUsage = Twine(ccInfo.argRegsUsage);
        std::string brName = callerInfo.getExitName();

        std::string idxName, entryName;
        if (!calleeInfo.name.empty()) // call to SPM
        {
            idxName = calleeInfo.getIndexName(callee.getName());
            entryName = calleeInfo.getEntryName();
        }
        else
        {
            idxName = callee.getName();
            entryName = "__unprotected_entry";
        }

        stubAsm = Twine("\t.align 2\n"
                        "\t.section " + sectionName + ",\"ax\",@progbits\n"
                        "\t.weak " + stubName + + "\n" +
                        stubName + ":\n"
                        "\tpush r6\n"
                        "\tpush r7\n"
                        "\tpush r8\n"
                        "\tmov #" + idxName + ", r6\n"
                        "\tmov #" + regsUsage + ", r7\n"
                        "\tmov #" + entryName + ", r8\n"
                        "\tbr #" + brName + "\n"
                       ).str();

        stub = Function::Create(callee.getFunctionType(),
                                Function::ExternalLinkage, stubName, m);
    }

    if (!stubAsm.empty())
        m->appendModuleInlineAsm(stubAsm);

    stubs[pair] = stub;
    return stub;
}

bool SpmCreator::isInSpm(const GlobalValue& gv)
{
    if (gv.isDeclaration())
        return false;

    if (gv.hasUnnamedAddr())
        return false;

    return true;
}

SpmInfo SpmCreator::getSpmInfo(const GlobalValue* gv)
{
    auto it = spmInfo.find(gv);
    if (it != spmInfo.end())
        return it->second;

    AnnotationParser& ap = getAnalysis<AnnotationParser>();
    SpmInfo info;
    for (const Annotation& annot : ap.getAnnotations(gv))
    {
        auto pair = annot.value.split(':');
        if (pair.second.empty())
            continue;

        if (pair.first == "spm_entry")
            info.isEntry = true;
        else if (pair.first != "spm")
            continue;

        // found SPM annotation, check if it is the only one
        if (info.isInSpm)
            report_fatal_error("Multiple SPM annotations on " + gv->getName());

        info.name = pair.second;
        info.isInSpm = true;
    }

    spmInfo.insert({gv, info});
    return info;
}
