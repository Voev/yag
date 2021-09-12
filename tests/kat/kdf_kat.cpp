#include <utilities/ossl_param.hpp>
#include "kdf_kat.hpp"

static constexpr const char* kdfAlg = "algorithm";
static constexpr const char* kdfKeySize = "keysize";
static constexpr const char* kdfParam = "param";
static constexpr const char* kdfEtalon = "expected";

KdfKAT::KdfKAT(const FileParser::Section& section)
{
    for (const auto& sectionPair : section)
    {
        if (0 == sectionPair.first.compare(kdfAlg))
        {
            kdf_.reset(
                EVP_KDF_fetch(nullptr, sectionPair.second.c_str(), nullptr));
        }
        else if (0 == sectionPair.first.compare(kdfKeySize))
        {
            keySize_ = static_cast<size_t>(std::stoul(sectionPair.second));
        }
        else if (0 == sectionPair.first.compare(kdfEtalon))
        {
            long size = 0;
            uint8_t* ptr =
                OPENSSL_hexstr2buf(sectionPair.second.c_str(), &size);
            expected_.assign(ptr, ptr + size);
        }
        else if (0 == sectionPair.first.rfind(kdfParam))
        {
            params_.push_back(sectionPair.second);
        }
    }
}

void KdfKAT::Execute()
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf_.get()));
    ASSERT_NE(ctx.get(), nullptr);

    size_t size = EVP_KDF_CTX_get_kdf_size(ctx.get());
    ASSERT_GT(size, 0);
    ASSERT_GE(size, keySize_);
    actual_.resize(keySize_);

    ossl::Params params(params_, EVP_KDF_CTX_settable_params(ctx.get()));
    ASSERT_LT(0, EVP_KDF_CTX_set_params(ctx.get(), params.data()));
    ASSERT_LT(0, EVP_KDF_derive(ctx.get(), actual_.data(), keySize_, nullptr));
}
