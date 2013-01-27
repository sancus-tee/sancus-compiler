#include "SpmInfo.h"

std::string SpmInfo::getDataSection() const
{
    return ".spm." + name + ".data";
}

std::string SpmInfo::getTextSection() const
{
    return name.empty() ? ".text" : ".spm." + name + ".text";
}

std::string SpmInfo::getTableSection() const
{
    return ".spm." + name + ".table";
}

std::string SpmInfo::getStackName() const
{
    return "__spm_" + name + "_stack";
}

std::string SpmInfo::getSpName() const
{
    return "__spm_" + name + "_sp";
}

std::string SpmInfo::getEntryName() const
{
    return "__spm_" + name + "_entry";
}

std::string SpmInfo::getExitName() const
{
    return "__spm_" + name + "_exit";
}

std::string SpmInfo::getIndexName(const std::string& entry) const
{
    return "__spm_" + name + "_entry_" + entry + "_idx";
}

std::string SpmInfo::getCalleeStubName(const std::string& callee) const
{
    std::string me = name.empty() ? "__unprotected" : "__spm_" + name;
    return me + "_stub_" + callee;
}
