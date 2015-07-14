#define DEBUG_TYPE "sm-creator"

#include "FunctionCcInfo.h"
#include "SancusModuleInfo.h"
#include "AnnotationParser.h"

#include <llvm/Pass.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/TypeBuilder.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InlineAsm.h>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Debug.h>

#include <sstream>

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
    Constant* getSymbolAddress(Module& m, StringRef name);
    std::string fixSymbolName(const std::string& name);
    CallSite handleSancusCall(CallSite cs);

    typedef std::map<const GlobalValue*, SancusModuleInfo> InfoMap;
    InfoMap modulesInfo;

    typedef std::vector<Function*> EntryList;
    EntryList entries;
    typedef std::map<std::pair<std::string, Function*>, Function*> StubMap;
    StubMap stubs;

    Module* module;
    Type* wordTy;
    Type* byteTy;
    Type* voidPtrTy;
    FunctionType* verifyTy;
};

}

char SancusModuleCreator::ID = 0;
static RegisterPass<SancusModuleCreator> SMC("create-sm",
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
    module = &m;
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

    if (modified)
    {
        // module-level inline assembly gets inserted after the .text directive.
        // this means that if the added assembly changes the section, this
        // section will be used for the rest of the file if we don't add the
        // .text declaration after it
        m.appendModuleInlineAsm(".text\n");
    }

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
    if (info.isInSm)
    {
        f.setSection(info.getTextSection());
        modified = true;
    }
    if (info.isEntry)
        entries.push_back(&f);

    std::map<Instruction*, Instruction*> verifications;
    std::map<Instruction*, Instruction*> replacements;

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

            std::string locStr;
            if (auto loc = inst->getDebugLoc())
            {
                Twine t(" (" + Twine(loc.getLine()) + ":" +
                        Twine(loc.getCol()) + ")");
                locStr = t.str();
            }

            // FIXME this warning is too strict since it also fires on "normal"
            // function pointers. we should try to warn only when a function
            // pointer is used inside an SM or is created from an SM function.
            errs() << "WARNING: In function " << f.getName() << locStr
                   << ": Function pointers not supported yet\n";
            continue;
        }
        else if (callee->isIntrinsic())
            continue;
        else if (callee->getName() == "sancus_call")
        {
            replacements[cs.getInstruction()] =
                handleSancusCall(cs).getInstruction();
            continue;
        }

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

    for (auto pair : replacements)
    {
        auto oldInst = pair.first;
        auto newInst = pair.second;
        newInst->insertBefore(oldInst);
        oldInst->replaceAllUsesWith(newInst);
        oldInst->eraseFromParent();
    }

    return modified;
}

bool SancusModuleCreator::handleData(GlobalVariable& gv)
{
    SancusModuleInfo info = getSancusModuleInfo(&gv);
    if (!info.isInSm)
        return false;

    if (gv.hasCommonLinkage())
        gv.setLinkage(GlobalValue::WeakAnyLinkage);

    gv.setSection(info.getDataSection());
    return true;
}

void SancusModuleCreator::createFunctionTable(Module& m)
{
    LLVMContext& ctx = m.getContext();

    // struct SmFunctionInfo
    // {
    //     void* address;
    //     unsigned arg_length;
    //     unsigned ret_regs;
    // };
    Type* funcInfoFields[] = {voidPtrTy, wordTy, wordTy};

    StructType* funcInfoTy = StructType::get(ctx, funcInfoFields,
                                             /*isPacked=*/true);

    // create a global SM function table for every SM and initialize it
    // initializers for the funcs[] array.
    // map from section name to initializer
    std::map<std::string, std::vector<Constant*>> funcsEls;
    for (Function* f : entries)
    {
        SancusModuleInfo info = getSancusModuleInfo(f);
        assert(info.isEntry && "Asking function table for non-entry");

        // initializer for the SmFunctionInfo struct
        FunctionCcInfo ccInfo(f);
        Constant* funcFields[] = {ConstantExpr::getBitCast(f, voidPtrTy),
                                  ConstantInt::get(wordTy, ccInfo.argsLength),
                                  ConstantInt::get(wordTy, ccInfo.retRegsUsage)};
        funcsEls[info.getTableSection()]
            .push_back(ConstantStruct::get(funcInfoTy, funcFields));
    }

    for (const auto& it : funcsEls)
    {
        // struct SmFunctionInfo funcs[];
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

    if (callerInfo.name == calleeInfo.name) // call within SM/unprotected
        stub = &callee;
    else if (callerInfo.name.empty()) // call unprotected -> SM
    {
        if (!calleeInfo.isEntry)
        {
            report_fatal_error("In function " + caller.getName() +
                               ": Calling non-entry function " +
                               callee.getName() + " of SM " +
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
    else // call SM -> SM/unprotected
    {
        std::string sectionName = callerInfo.getTextSection();
        std::string stubName = callerInfo.getCalleeStubName(calleeName);
        Twine regsUsage = Twine(ccInfo.argRegsUsage);
        std::string brName = callerInfo.getExitName();

        std::string idxName, entryName;
        if (!calleeInfo.name.empty()) // call to SM
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
                           "supported for SMs.");
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

    auto& ap = getAnalysis<AnnotationParser>();
    SancusModuleInfo info;
    const auto annotations = ap.getAnnotations(gv);

    if (annotations.size() > 0)
    {
        // check if the annotations are consistent
        auto ref = annotations.front();
        auto isOk = true;

        for (auto it = annotations.begin() + 1; it < annotations.end(); ++it)
        {
            auto annotation = *it;

            if (annotation.value != ref.value)
            {
                std::stringstream msg;
                msg << annotation.file.str() << ":" << annotation.line << ": "
                    << "Annotation '" << annotation.value.str()
                    << "' on function '" << gv->getName().str()
                    << "' is inconsistent with the previous annotation '"
                    << ref.value.str();

                module->getContext().emitError(msg.str());
                isOk = false;
                break;
            }
        }

        if (isOk)
        {
            auto pair = ref.value.split(':');

            // ignore invalid annotations
            if (!pair.second.empty() &&
                (pair.first == "sm" || pair.first == "sm_entry"))
            {
                info.isEntry = pair.first == "sm_entry";
                info.name = fixSymbolName(pair.second);
                info.isInSm = true;
            }
        }
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
    if (!callerInfo.isInSm ||
        !calleeInfo.isInSm ||
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

    // argument 1: address of expected MAC
    Value* mac =
        getSymbolAddress(m, callerInfo.getCalleeMacName(calleeInfo.name));

    // argument 2: address of SM
    Value* sm = getSymbolAddress(m, calleeInfo.getEntryName());

    // argument 3: address of stored ID
    Value* id =
        getSymbolAddress(m, callerInfo.getCalleeIdName(calleeInfo.name));

    Value* args[] = {mac, sm, id};
    return CallInst::Create(verifyStub, args);
}

Constant* SancusModuleCreator::getSymbolAddress(Module& m, StringRef name)
{
    GlobalVariable* gv = m.getGlobalVariable(name);

    if (gv == nullptr)
    {
        gv = new GlobalVariable(m, byteTy, /*isConstant=*/false,
                                GlobalVariable::ExternalLinkage,
                                /*Initializer=*/nullptr, name);
    }

    return ConstantExpr::getBitCast(gv, voidPtrTy);
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

CallSite SancusModuleCreator::handleSancusCall(CallSite cs)
{
    assert(cs.arg_size() >= 2 && "sancus_call needs at least 2 arguments");

    auto numAsmArgs = cs.arg_size() - 2;

    if (numAsmArgs > 3)
    {
        report_fatal_error("Currently, maximum 3 arguments are supported by "
                           "sancus_call");
    }

    auto argTys = std::vector<Type*>{voidPtrTy, wordTy};
    auto entryVal = cs.getArgument(0);
    auto indexVal = cs.getArgument(1);
    auto args = std::vector<Value*>{entryVal, indexVal};

    auto inputConstraints = std::string{",r,r"};
    std::ostringstream argsAsm;
    auto regsUsage = unsigned{0x10};
    auto clobbers = std::string{",~{r6},~{r7},~{r8},~{r15}"};
    auto callerInfo = getSancusModuleInfo(cs.getCaller());

    for (decltype(numAsmArgs) i = 0; i < numAsmArgs; i++)
    {
        auto arg = cs.getArgument(i + 2);
        auto argTy = arg->getType();

        // TODO FunctionCcInfo should be used to check the argument. This is not
        // possible currently since it takes a Function* as argument.
        if (argTy->getPrimitiveSizeInBits() != 16 && !argTy->isPointerTy())
            report_fatal_error("Illegal argument type in call to sancus_call");

        inputConstraints += ",r";

        std::ostringstream regStream;
        regStream << "r" << 15 - i;
        auto regStr = regStream.str();

        if (regStr != "r15")
            clobbers += ",~{" + regStr + "}";

        argsAsm << "mov $" << i + 3 << ", " << regStr << "\n\t";
        args.push_back(arg);
        argTys.push_back(argTy);

        // see sm_exit.s to understand how this value is used.
        regsUsage >>= 1;
    }

    auto asmStr = Twine("push #1f\n\t"
                        "push r6\n\t"
                        "push r7\n\t"
                        "push r8\n\t"
                        "mov $2, r6\n\t"
                        "mov #" + Twine(regsUsage) + ", r7\n\t"
                        "mov $1, r8\n\t" + argsAsm.str() +
                        "br #" + callerInfo.getExitName() + "\n"
                        "1:\n\t"
                        "mov r15, $0"
                        ).str();

    auto constraintsStr = "=r" + inputConstraints + clobbers;
    auto resTy = wordTy;
    auto asmFuncTy = FunctionType::get(resTy, argTys, /*isVarArg=*/false);

    // NOTE hasSideEffects has to be true because the inline assembly may be
    // optimised away otherwise
    auto inlineAsm = InlineAsm::get(asmFuncTy, asmStr, constraintsStr,
                                    /*hasSideEffects=*/true);

    auto asmCall = CallInst::Create(inlineAsm, args);
    return CallSite(asmCall);
}
