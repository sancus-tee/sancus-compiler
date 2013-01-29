#define DEBUG_TYPE "spm-creator"

#include "FunctionCcInfo.h"
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

    bool handleFunction(Function& f);
    bool handleData(GlobalVariable& gv);
    void createFunctionTable(Module& m);
    Function* getStub(Function& caller, Function& callee);
    SpmInfo getSpmInfo(const GlobalValue* gv);
    Function* getCalledFunction(CallSite cs);

    typedef std::map<const GlobalValue*, SpmInfo> InfoMap;
    InfoMap spmInfo;

    typedef std::vector<Function*> EntryList;
    EntryList entries;
    typedef std::map<std::pair<std::string, Function*>, Function*> StubMap;
    StubMap stubs;
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
    bool modified = false;

    for (GlobalVariable& gv : m.getGlobalList())
        modified |= handleData(gv);
    for (Function& f : m.getFunctionList())
        modified |= handleFunction(f);

    createFunctionTable(m);

    return modified;
}

bool SpmCreator::handleFunction(Function& f)
{
    if (f.isIntrinsic() || f.isDeclaration())
        return false;

    bool modified = false;

    SpmInfo info = getSpmInfo(&f);
    if (info.isInSpm)
    {
        f.setSection(info.getTextSection());
        modified = true;
    }
    if (info.isEntry)
        entries.push_back(&f);

    for (inst_iterator it = inst_begin(f), end = inst_end(f); it != end; ++it)
    {
        CallSite cs(&*it);
        if (!cs)
            continue;

        Function* callee = getCalledFunction(cs);
        if (callee == nullptr)
        {
            if (CallInst* ci = cast<CallInst>(&*it))
            {
                if (ci->isInlineAsm())
                    continue;
            }

            report_fatal_error("In function " + f.getName() +
                               ": Function pointers not supported yet");
        }
        else if (callee->isIntrinsic())
            continue;

        Function* stub = getStub(f, *callee);
        cs.setCalledFunction(stub);

        if (stub != callee)
            modified = true;
    }

    return modified;
}

bool SpmCreator::handleData(GlobalVariable& gv)
{
    SpmInfo info = getSpmInfo(&gv);
    if (!info.isInSpm)
        return false;

    if (gv.hasCommonLinkage())
        gv.setLinkage(GlobalValue::WeakAnyLinkage);

    gv.setSection(info.getDataSection());
    return true;
}

void SpmCreator::createFunctionTable(Module& m)
{
    LLVMContext& ctx = m.getContext();
    Type* wordTy = TypeBuilder<types::i<16>, true>::get(ctx);
    Type* voidPtrTy = TypeBuilder<types::i<8>*, true>::get(ctx);

    // struct SpmFunctionInfo
    // {
    //     void* address;
    //     unsigned arg_length;
    //     unsigned ret_regs;
    // };
    Type* funcInfoFields[] = {voidPtrTy, wordTy, wordTy};

    StructType* funcInfoTy = StructType::get(ctx, funcInfoFields,
                                             /*isPacked=*/true);

    // create a global spm function table for every spm and initialize it
    // initializers for the funcs[] array.
    // map from section name to initializer
    std::map<std::string, std::vector<Constant*>> funcsEls;
    for (Function* f : entries)
    {
        SpmInfo info = getSpmInfo(f);
        assert(info.isEntry && "Asking function table for non-entry");

        // initializer for the SpmFunctionInfo struct
        FunctionCcInfo ccInfo(f);
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

Function* SpmCreator::getStub(Function& caller, Function& callee)
{
    Module* m = caller.getParent();
    SpmInfo callerInfo = getSpmInfo(&caller);
    SpmInfo calleeInfo = getSpmInfo(&callee);

    auto pair = std::make_pair(callerInfo.name, &callee);
    StubMap::iterator it = stubs.find(pair);
    if (it != stubs.end())
        return it->second;

    Function* stub = nullptr;
    std::string stubAsm;

    if (callerInfo.name == calleeInfo.name) // call within SPM/unprotected
        stub = &callee;
    else if (callerInfo.name.empty()) // call unprotected -> SPM
    {
        if (!calleeInfo.isEntry)
        {
            report_fatal_error("In function " + caller.getName() +
                               ": Calling non-entry function " +
                               callee.getName() + " of SPM " +
                               callerInfo.name);
        }

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
        FunctionCcInfo ccInfo(&callee);
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

Function* SpmCreator::getCalledFunction(CallSite cs)
{
    assert(cs && "Not a call site");

    if (Function* f = cs.getCalledFunction())
        return f;

    if (ConstantExpr* ce = dyn_cast<ConstantExpr>(cs.getCalledValue()))
    {
        if (ce->isCast())
        {
            if (Function* f = dyn_cast<Function>(ce->getOperand(0)))
                return f;
        }
    }

    return nullptr;
}
