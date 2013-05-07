#include "SancusModuleInfo.h"

std::string SancusModuleInfo::getDataSection() const
{
    return ".spm." + name + ".data";
}

std::string SancusModuleInfo::getTextSection() const
{
    return name.empty() ? ".text" : ".spm." + name + ".text";
}

std::string SancusModuleInfo::getTableSection() const
{
    return ".spm." + name + ".table";
}

std::string SancusModuleInfo::getStackName() const
{
    return "__spm_" + name + "_stack";
}

std::string SancusModuleInfo::getSpName() const
{
    return "__spm_" + name + "_sp";
}

std::string SancusModuleInfo::getEntryName() const
{
    return "__spm_" + name + "_entry";
}

std::string SancusModuleInfo::getExitName() const
{
    return "__spm_" + name + "_exit";
}

std::string SancusModuleInfo::getVerifyName() const
{
    return "__spm_" + name + "_verify";
}

std::string SancusModuleInfo::getIndexName(const std::string& entry) const
{
    return "__spm_" + name + "_entry_" + entry + "_idx";
}

std::string SancusModuleInfo::getCalleeIdName(const std::string& callee) const
{
    return "__spm_" + name + "_id_" + callee;
}

std::string SancusModuleInfo::getCalleeHmacName(const std::string& callee) const
{
    return "__spm_" + name + "_hmac_" + callee;
}

std::string SancusModuleInfo::getCalleeStubName(const std::string& callee) const
{
    std::string me = name.empty() ? "__unprotected" : "__spm_" + name;
    return me + "_stub_" + callee;
}
