#include "file_parser.hpp"
#include <algorithm>
#include <fstream>

FileParser& FileParser::Instance()
{
    static FileParser instance;
    return instance;
}

void FileParser::Parse(const std::string& filename)
{
    std::ifstream file;

    file.open(filename, std::ifstream::in);
    if (!file.is_open()) {
        throw std::runtime_error("failed to open file: " + filename);
    }

    std::string line;
    std::string section;

    auto ltrim = [](std::string& s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char ch) {
                    return !std::isspace(ch);
                }));
    };

    auto rtrim = [](std::string& s) {
        s.erase(std::find_if(s.rbegin(), s.rend(),
                             [](char ch) { return !std::isspace(ch); })
                    .base(),
                s.end());
    };

    while (std::getline(file, line)) {
        ltrim(line);
        rtrim(line);

        const auto length = line.length();
        if (length > 0) {
            const auto pos =
                std::find_if(line.begin(), line.end(),
                             [this](char ch) { return ch == '='; });

            const auto& front = line.front();
            if (front == '#') {
                // Fall through
            }
            else if (front == '[') {
                if (line.back() == ']')
                    section = line.substr(1, length - 2);
                else
                    throw std::runtime_error("incorrect format: " + line);
            }
            else if (pos != line.begin() && pos != line.end()) {
                std::string variable(line.begin(), pos);
                std::string value(pos + 1, line.end());

                rtrim(variable);
                ltrim(value);

                auto& sec = sections_[section];
                if (sec.find(variable) == sec.end())
                    sec.insert(std::make_pair(variable, value));
                else
                    throw std::runtime_error("incorrect format: " + line);
            }
            else {
                throw std::runtime_error("incorrect format: " + line);
            }
        }
    }
}

FileParser::Sections FileParser::GetSections() const { return sections_; }

FileParser::Section FileParser::GetSectionBody(const std::string& section) const
{
    return sections_.at(section);
}