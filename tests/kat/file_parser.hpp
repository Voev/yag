#pragma once
#include <map>
#include <string>
#include <vector>

class FileParser
{
  public:
    using Section = std::map<std::string, std::string>;
    using Sections = std::map<std::string, Section>;

  public:
    static FileParser& Instance();
    ~FileParser() = default;

    void Parse(const std::string& filename);
    Sections GetSections() const;
    Section GetSectionBody(const std::string& section) const;

  private:
    FileParser() = default;

  private:
    Sections sections_;
};
