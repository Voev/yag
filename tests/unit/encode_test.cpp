#include <gtest/gtest.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <vector>

#include <utilities/name_generator.hpp>
#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>

using BaseParam = std::pair<const char*, const char*>;

static std::string
BaseNameGenerator(const testing::TestParamInfo<BaseParam>& info)
{
    auto param = info.param;
    std::string name = param.second;
    NameGeneratorFiltering(name);
    return name;
}

class EncodeDecodeTest : public testing::TestWithParam<BaseParam>
{
  public:
    void SetUp() {}

    void TearDown() { ERR_print_errors_fp(stderr); }
};

TEST_P(EncodeDecodeTest, EncodePrivateKeyToText)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr out(BIO_new(BIO_s_null()));
    ASSERT_LT(0, EVP_PKEY_print_private(out.get(), pkey.get(), 0, nullptr));
}

TEST_P(EncodeDecodeTest, EncodePublicKeyToText)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr out(BIO_new(BIO_s_null()));
    ASSERT_LT(0, EVP_PKEY_print_public(out.get(), pkey.get(), 0, nullptr));
}

TEST_P(EncodeDecodeTest, EncodeParametersToText)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateParameters(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr out(BIO_new(BIO_s_null()));
    ASSERT_LT(0, EVP_PKEY_print_params(out.get(), pkey.get(), 0, nullptr));
}

TEST_P(EncodeDecodeTest, EncodePrivateKeyToDer)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, i2d_PKCS8PrivateKeyInfo_bio(bio.get(), pkey.get()));
}

TEST_P(EncodeDecodeTest, EncodePrivateKeyToPem)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr,
                                          nullptr, 0, nullptr, nullptr));
}

TEST_P(EncodeDecodeTest, EncodePublicKeyToDer)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    X509_PUBKEY* pubkey = nullptr;
    X509_PUBKEY_set(&pubkey, pkey.get());
    ossl::X509PubKeyPtr pub(pubkey);
    ASSERT_NE(pub.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, i2d_X509_PUBKEY_bio(bio.get(), pub.get()));
}

TEST_P(EncodeDecodeTest, EncodePublicKeyToPem)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    X509_PUBKEY* pubkey = nullptr;
    X509_PUBKEY_set(&pubkey, pkey.get());
    ossl::X509PubKeyPtr pub(pubkey);
    ASSERT_NE(pub.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, PEM_write_bio_X509_PUBKEY(bio.get(), pub.get()));
}

TEST_P(EncodeDecodeTest, EncodeKeyParametersToDer)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateParameters(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, i2d_KeyParams_bio(bio.get(), pkey.get()));
}

TEST_P(EncodeDecodeTest, DISABLED_DecodeKeyParametersFromDer)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateParameters(param.first, param.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);
    ASSERT_LT(0, i2d_KeyParams_bio(bio.get(), pkey.get()));

    pkey.reset(d2i_KeyParams_bio(OBJ_sn2nid(param.first), nullptr, bio.get()));
    ASSERT_NE(pkey.get(), nullptr);
}

const std::vector<BaseParam> gTestParams = {
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD}};

INSTANTIATE_TEST_SUITE_P(EncodeDecodeTests, EncodeDecodeTest,
                         testing::ValuesIn(gTestParams), BaseNameGenerator);

struct EncoderOutParam
{
    const char* outputType = nullptr;
    const char* outputStructure = nullptr;
    const int selection = 0;
};

static const std::vector<EncoderOutParam> gTestEncoderOutParams = {
    {"TEXT", nullptr, OSSL_KEYMGMT_SELECT_PRIVATE_KEY},
    {"PEM", "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY},
    {"DER", "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY},
    {"TEXT", nullptr, OSSL_KEYMGMT_SELECT_PUBLIC_KEY},
    {"PEM", "SubjectPublicKeyInfo", OSSL_KEYMGMT_SELECT_PUBLIC_KEY},
    {"DER", "SubjectPublicKeyInfo", OSSL_KEYMGMT_SELECT_PUBLIC_KEY},
    {"TEXT", nullptr, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"PEM", "type-specific", OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"DER", "type-specific", OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS}};

using ProvidedEncodeTestParam = std::tuple<BaseParam, EncoderOutParam>;

class ProvidedEncodeTest
    : public testing::TestWithParam<ProvidedEncodeTestParam>
{
  public:
    void SetUp() {}

    void TearDown() { ERR_print_errors_fp(stderr); }
};

TEST_P(ProvidedEncodeTest, ProvidedEncodeToBio)
{
    auto param = GetParam();
    auto& algParam = std::get<0>(param);
    auto& outParam = std::get<1>(param);

    ossl::EvpPkeyPtr pkey(
        ossl::GenerateKeyPair(algParam.first, algParam.second));
    ASSERT_NE(pkey.get(), nullptr);

    ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr);

    ossl::EncoderCtxPtr ctx(OSSL_ENCODER_CTX_new_for_pkey(
        pkey.get(), outParam.selection, outParam.outputType,
        outParam.outputStructure, nullptr));
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_NE(0, OSSL_ENCODER_CTX_get_num_encoders(ctx.get()));
    ASSERT_LT(0, OSSL_ENCODER_to_bio(ctx.get(), bio.get()));
}

INSTANTIATE_TEST_SUITE_P(
    ProvidedEncodeTests, ProvidedEncodeTest,
    testing::Combine(testing::ValuesIn(gTestParams),
                     testing::ValuesIn(gTestEncoderOutParams)));
