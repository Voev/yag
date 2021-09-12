#include "digest_kat.hpp"
#include <algorithm>
#include <iostream>
#include <utilities/ossl_pointers.hpp>

static constexpr const char* digestAlg = "algorithm";
static constexpr const char* digestInput = "message";
static constexpr const char* digestEtalon = "expected";

DigestKAT::DigestKAT(const FileParser::Section& section)
{
    for (const auto& sectionPair : section)
    {
        if (0 == sectionPair.first.compare(digestAlg))
        {
            digest_.reset(
                EVP_MD_fetch(nullptr, sectionPair.second.c_str(), nullptr));
        }
        else if (0 == sectionPair.first.compare(digestInput))
        {
            long size = 0;
            uint8_t* ptr =
                OPENSSL_hexstr2buf(sectionPair.second.c_str(), &size);
            message_.assign(ptr, ptr + size);
        }
        else if (0 == sectionPair.first.compare(digestEtalon))
        {
            long size = 0;
            uint8_t* ptr =
                OPENSSL_hexstr2buf(sectionPair.second.c_str(), &size);
            expected_.assign(ptr, ptr + size);
        }
    }
}

void DigestKAT::Execute()
{
    unsigned int size = 0;
    actual_.resize(EVP_MD_size(digest_.get()));

    ossl::EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_DigestInit(ctx.get(), digest_.get()));
    ASSERT_LT(0, EVP_DigestUpdate(ctx.get(), message_.data(), message_.size()));
    ASSERT_LT(0, EVP_DigestFinal_ex(ctx.get(), actual_.data(), &size));
    ASSERT_EQ(size, actual_.size());
}
