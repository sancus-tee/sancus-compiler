#define DEBUG_TYPE "spm-creator"

#include "FunctionCcInfo.h"
#include "SancusModuleInfo.h"
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

struct SancusModuleCreator : ModulePass
{
    static char ID;

    SancusModuleCreator();

    virtual void getAnalysisUsage(AnalysisUsage& au) const;
    virtual bool runOnModule(Module& m);

    bool handleFunction(Function& f);
    bool handleData(GlobalVariable& gv);
    void createFunctionTable(Module& m);
    Function* getStub(Function& caller, Function& callee);
    SancusModuleInfo getSancusModuleInfo(const GlobalValue* gv);
    Function* getCalledFunction(CallSite cs);
    Instruction* getVerification(SancusModuleInfo callerInfo,
                                 SancusModuleInfo calleeInfo,
                                 Module& m);
    GlobalVariable* getSymbolAddress(Module& m, StringRef name);
    std::string fixSymbolName(const std::string& name);

    typedef std::map<const GlobalValue*, SancusModuleInfo> InfoMap;
    InfoMap modulesInfo;

    typedef std::vector<Function*> EntryList;
    EntryList entries;
    typedef std::map<std::pair<std::string, Function*>, Function*> StubMap;
    StubMap stubs;

    Type* wordTy;
    Type* byteTy;
    Type* voidPtrTy;
    FunctionType* verifyTy;
};

}

char SancusModuleCreator::ID = 0;
static RegisterPass<SancusModuleCreator> SPM("create-sm",
                                             "Create Sancus module");

SancusModuleCreator::SancusModuleCreator() : ModulePass(ID)
{
}

void SancusModuleCreator::getAnalysisUsage(AnalysisUsage& au) const
{
    au.addRequired<AnnotationParser>();
}

bool SancusModuleCreator::runOnModule(Module& m)
{
    LLVMContext& ctx = m.getContext();
    wordTy = TypeBuilder<types::i<16>, true>::get(ctx);
    byteTy = TypeBuilder<types::i<8>, true>::get(ctx);
    voidPtrTy = TypeBuilder<types::i<8>*, true>::get(ctx);

    Type* argTys[] = {voidPtrTy, voidPtrTy, voidPtrTy};
    verifyTy = FunctionType::get(Type::getVoidTy(ctx), argTys,
                                 /*isVarArg=*/false);

    bool modified = false;

    for (GlobalVariable& gv : m.getGlobalList())
        modified |= handleData(gv);
    for (Function& f : m.getFunctionList())
        modified |= handleFunction(f);

    createFunctionTable(m);

    return modified;
}

bool SancusModuleCreator::handleFunction(Function& f)
{
    if (f.isIntrinsic() || f.isDeclaration())
        return false;

    bool modified = false;

    // HACK: clang fails to add the needed attributes to main(), add them here
    if (f.getName() == "main")
    {
        f.setSection(".init9");
        f.setAlignment(2);
        modified = true;
    }

    SancusModuleInfo info = getSancusModuleInfo(&f);
    if (info.isInSpm)
    {
        f.setSection(info.getTextSection());
        modified = true;
    }
    if (info.isEntry)
        entries.push_back(&f);

    std::map<Instruction*, Instruction*> verifications;

    for (inst_iterator it = inst_begin(f), end = inst_end(f); it != end; ++it)
    {
        Instruction* inst = &*it;
        CallSite cs(inst);
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

            DebugLoc loc = inst->getDebugLoc();
            Twine locStr;
            if (!loc.isUnknown())
            {
                locStr = " (" + Twine(loc.getLine()) + ":" +
                         Twine(loc.getCol()) + ")";
            }

            errs() << "WARNING: In function " << f.getName() << locStr
                   << ": Function pointers not supported yet\n";
            continue;
        }
        else if (callee->isIntrinsic())
            continue;

        if (Instruction* v = getVerification(info, getSancusModuleInfo(callee),
                                             *f.getParent()))
        {
            verifications[inst] = v;
        }

        Function* stub = getStub(f, *callee);
        cs.setCalledFunction(stub);

        if (stub != callee)
            modified = true;
    }

    for (auto pair : verifications)
        pair.second->insertBefore(pair.first);

    return modified;
}

bool SancusModuleCreator::handleData(GlobalVariable& gv)
{
    SancusModuleInfo info = getSancusModuleInfo(&gv);
    if (!info.isInSpm)
        return false;

    if (gv.hasCommonLinkage())
        gv.setLinkage(GlobalValue::WeakAnyLinkage);

    gv.setSection(info.getDataSection());
    return true;
}

void SancusModuleCreator::createFunctionTable(Module& m)
{
    LLVMContext& ctx = m.getContext();

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
        SancusModuleInfo info = getSancusModuleInfo(f);
        assert(info.isEntry && "Asking function table for non-entry");

        // initializer for the SpmFunctionInfo struct
        FunctionCcInfo ccInfo(f);
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

Function* SancusModuleCreator::getStub(Function& caller, Function& callee)
{
    Module* m = caller.getParent();
    SancusModuleInfo callerInfo = getSancusModuleInfo(&caller);
    SancusModuleInfo calleeInfo = getSancusModuleInfo(&callee);

    auto pair = std::make_pair(callerInfo.name, &callee);
    StubMap::iterator it = stubs.find(pair);
    if (it != stubs.end())
        return it->second;

    Function* stub = nullptr;
    std::string stubAsm;

    FunctionCcInfo ccInfo(&callee);
    std::string calleeName = fixSymbolName(callee.getName());

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
        std::string stubName = callerInfo.getCalleeStubName(calleeName);
        std::string idxName = calleeInfo.getIndexName(calleeName);
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
        std::string sectionName = callerInfo.getTextSection();
        std::string stubName = callerInfo.getCalleeStubName(calleeName);
        Twine regsUsage = Twine(ccInfo.argRegsUsage);
        std::string brName = callerInfo.getExitName();

        std::string idxName, entryName;
        if (!calleeInfo.name.empty()) // call to SPM
        {
            idxName = calleeInfo.getIndexName(calleeName);
            entryName = calleeInfo.getEntryName();
        }
        else
        {
            idxName = calleeName;
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

    if (stub != &callee && (ccInfo.argsLength != 0 ||
                            ccInfo.retLength != 0  ||
                            callee.isVarArg()))
    {
        report_fatal_error("Call from " + caller.getName() + " to " +
                           calleeName + " uses the stack for parameter "
                           "and/or return value passing. This is not "
                           "supported for SPMs.");
    }

    if (!stubAsm.empty())
        m->appendModuleInlineAsm(stubAsm);

    stubs[pair] = stub;
    return stub;
}

SancusModuleInfo SancusModuleCreator::getSancusModuleInfo(const GlobalValue* gv)
{
    auto it = modulesInfo.find(gv);
    if (it != modulesInfo.end())
        return it->second;

    AnnotationParser& ap = getAnalysis<AnnotationParser>();
    SancusModuleInfo info;
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

        info.name = fixSymbolName(pair.second);
        info.isInSpm = true;
    }

    modulesInfo.insert({gv, info});
    return info;
}

Function* SancusModuleCreator::getCalledFunction(CallSite cs)
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

Instruction* SancusModuleCreator::getVerification(SancusModuleInfo callerInfo,
                                         SancusModuleInfo calleeInfo,
                                         Module& m)
{
    if (!callerInfo.isInSpm ||
        !calleeInfo.isInSpm ||
        callerInfo.name == calleeInfo.name)
    {
        return nullptr;
    }

    std::string verifyName = callerInfo.getVerifyName();
    Function* verifyStub = m.getFunction(verifyName);

    if (verifyStub == nullptr)
    {
        verifyStub = Function::Create(verifyTy, Function::ExternalLinkage,
                                      verifyName, &m);
    }

    // argument 1: address of expected HMAC
    Value* hmac =
        getSymbolAddress(m, callerInfo.getCalleeHmacName(calleeInfo.name));

    // argument 2: address of SPM
    Value* spm = getSymbolAddress(m, calleeInfo.getEntryName());

    // argument 3: address of stored ID
    Value* id =
        getSymbolAddress(m, callerInfo.getCalleeIdName(calleeInfo.name));

    Value* args[] = {hmac, spm, id};
    return CallInst::Create(verifyStub, args);
}

GlobalVariable* SancusModuleCreator::getSymbolAddress(Module& m, StringRef name)
{
    if (GlobalVariable* gv = m.getGlobalVariable(name))
        return gv;

    return new GlobalVariable(m, byteTy, /*isConstant=*/false,
                              GlobalVariable::ExternalLinkage,
                              /*Initializer=*/nullptr, name);
}


std::string SancusModuleCreator::fixSymbolName(const std::string& name)
{
    assert(!name.empty() && "Empty symbol name?");

    // remove the \01 prefix that is used to mangle __asm declarations
    if (name.front() == '\01')
        return name.substr(1);
    else
        return name;
}

