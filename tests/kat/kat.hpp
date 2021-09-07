#pragma once
#include "file_parser.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

class KAT
{
  public:
    KAT() = default;
    virtual ~KAT() = default;
    virtual void Execute() = 0;

    void SetExecutable(bool executable)
    {
        executable_ = executable;
    }
    bool GetExecutable() const
    {
        return executable_;
    }
    bool CheckResult()
    {
        return actual_ == expected_;
    };
    std::vector<uint8_t> GetActual() const
    {
        return actual_;
    }
    std::vector<uint8_t> GetExpected() const
    {
        return expected_;
    }

  private:
    KAT(const KAT&) = delete;
    KAT(KAT&&) = delete;

    KAT& operator=(const KAT&) = delete;
    KAT& operator=(KAT&&) = delete;

  protected:
    std::vector<uint8_t> actual_;
    std::vector<uint8_t> expected_;

  private:
    bool executable_ = false;
};

class KATExecutor : public testing::TestWithParam<
                        std::pair<const std::string, FileParser::Section>>
{
  public:
    KATExecutor() = default;
    ~KATExecutor() = default;

    virtual void SetUp() override
    {
    }
    virtual void TearDown() override
    {
    }

    static std::unique_ptr<KAT> MakeKnownAnswerTest(
        std::pair<const std::string, FileParser::Section> param);

  private:
    std::unique_ptr<KAT> kat_;
};