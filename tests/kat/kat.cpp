#include "kat.hpp"
#include "digest_kat.hpp"
#include "kdf_kat.hpp"
#include "file_parser.hpp"
#include <gtest/gtest.h>
#include <utilities/name_generator.hpp>

static std::string
NameGenerator(const testing::TestParamInfo<
              std::pair<const std::string, FileParser::Section>>& info)
{
    std::string name = info.param.first;
    NameGeneratorFiltering(name);
    return name;
}

std::unique_ptr<KAT> KATExecutor::MakeKnownAnswerTest(
    std::pair<const std::string, FileParser::Section> param)
{
    if (param.first.find("digest") != std::string::npos)
        return std::make_unique<DigestKAT>(param.second);
    if (param.first.find("kdf") != std::string::npos)
        return std::make_unique<KdfKAT>(param.second);

    return nullptr;
}

template <class T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v)
{
    os << "[";
    for (typename std::vector<T>::const_iterator it = v.cbegin();
         it != v.cend(); ++it)
    {
        os << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>(*it);
    }
    os << "]";
    return os;
}

TEST_P(KATExecutor, KATs)
{
    try
    {
        auto kat = MakeKnownAnswerTest(GetParam());
        ASSERT_NE(kat, nullptr);
        if (kat->GetExecutable())
        {
            SUCCEED() << "Not supported";
        }
        kat->Execute();
        ASSERT_TRUE(kat->CheckResult())
            << "  Actual: " << kat->GetActual() << "\n"
            << "Expected: " << kat->GetExpected();
        SUCCEED();
    }
    catch (std::exception& exc)
    {
        FAIL() << exc.what();
    }
}

INSTANTIATE_TEST_CASE_P(KATs, KATExecutor,
                        testing::ValuesIn(FileParser::Instance().GetSections()),
                        NameGenerator);