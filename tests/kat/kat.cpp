#include "kat.hpp"
#include "digest_kat.hpp"
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
    return nullptr;
}

TEST_P(KATExecutor, KATs)
{
    try {
        auto kat = MakeKnownAnswerTest(GetParam());
        ASSERT_NE(kat, nullptr);
        if (kat->GetExecutable()) {
            SUCCEED() << "Not supported";
        }
        kat->Execute();
        ASSERT_TRUE(kat->CheckResult());
        SUCCEED();
    } catch (std::exception& exc) {
        FAIL() << exc.what();
    }
}

INSTANTIATE_TEST_CASE_P(KATs, KATExecutor,
                        testing::ValuesIn(FileParser::Instance().GetSections()),
                        NameGenerator);