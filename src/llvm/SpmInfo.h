#ifndef SPMINFO_H
#define SPMINFO_H

#include <string>

struct SpmInfo
{
    std::string name;
    bool isInSpm = false;
    bool isEntry = false;

    std::string getDataSection() const;
    std::string getTextSection() const;
    std::string getTableSection() const;
    std::string getStackName() const;
    std::string getSpName() const;
    std::string getEntryName() const;
    std::string getExitName() const;
    std::string getVerifyName() const;
    std::string getIndexName(const std::string& entry) const;
    std::string getCalleeIdName(const std::string& callee) const;
    std::string getCalleeHmacName(const std::string& callee) const;
    std::string getCalleeStubName(const std::string& callee) const;
};

#endif
