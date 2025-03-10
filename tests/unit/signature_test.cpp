#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <vector>

#include <utilities/crypto_manager.hpp>
#include <utilities/name_generator.hpp>
#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>

struct BaseParam
{
    const char* alg;
    const char* group;
    const char* digest;
};

static std::string
BaseNameGenerator(const testing::TestParamInfo<BaseParam>& info)
{
    auto param = info.param;
    std::string name = param.group;
    NameGeneratorFiltering(name);
    return name;
}

class SignatureTest : public testing::TestWithParam<BaseParam>
{
  public:
    void SetUp()
    {
    }

    void TearDown()
    {
        ERR_print_errors_fp(stderr);
    }
};

TEST_P(SignatureTest, SignVerifyEmptyMessageDigest_SelfTest)
{
    auto param = GetParam();

    auto pkey = ossl::GenerateKeyPair(param.alg, param.group);
    ASSERT_NE(pkey.get(), nullptr);

    auto md = ossl::CryptoManager::getInstance().fetchDigest(param.digest);
    ASSERT_NE(md.get(), nullptr);

    size_t siglen = 0;
    std::vector<uint8_t> msg(EVP_MD_size(md.get()), 0);
    std::vector<uint8_t> sig;

    auto ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_sign_init(ctx.get()));
    ASSERT_LT(
        0, EVP_PKEY_sign(ctx.get(), nullptr, &siglen, msg.data(), msg.size()));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_PKEY_sign(ctx.get(), sig.data(), &siglen, msg.data(),
                               msg.size()));

    ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_verify_init(ctx.get()));
    ASSERT_LT(0, EVP_PKEY_verify(ctx.get(), sig.data(), sig.size(), msg.data(),
                                 msg.size()));
}

TEST_P(SignatureTest, DISABLED_SignVerifyMessageDigestWithCopiedCtx_SelfTest)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.alg, param.group));
    ASSERT_NE(pkey.get(), nullptr);

    auto md = ossl::CryptoManager::getInstance().fetchDigest(param.digest);
    ASSERT_NE(md.get(), nullptr);

    size_t siglen = 0;
    std::vector<uint8_t> msg(EVP_MD_size(md.get()), 0);
    std::vector<uint8_t> sig;

    auto ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_sign_init(ctx.get()));
    ASSERT_LT(
        0, EVP_PKEY_sign(ctx.get(), nullptr, &siglen, msg.data(), msg.size()));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_PKEY_sign(ctx.get(), sig.data(), &siglen, msg.data(),
                               msg.size()));

    auto vctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());

    // Copying is not supported
    // ossl::EvpPkeyCtxPtr cctx(EVP_PKEY_CTX_dup(ctx.get()));

    ASSERT_NE(vctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_verify_init(vctx.get()));
    ASSERT_LT(0, EVP_PKEY_verify(vctx.get(), sig.data(), sig.size(), msg.data(),
                                 msg.size()));
}

TEST_P(SignatureTest, SignVerifyMessageDigest_SelfTest)
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey(ossl::GenerateKeyPair(param.alg, param.group));
    ASSERT_NE(pkey.get(), nullptr);

    auto md = ossl::CryptoManager::getInstance().fetchDigest(param.digest);
    ASSERT_NE(md.get(), nullptr);

    size_t siglen = 0;
    std::vector<uint8_t> msg(EVP_MD_size(md.get()), 0);
    std::vector<uint8_t> sig;

    ASSERT_LT(0, RAND_bytes(msg.data(), static_cast<int>(msg.size())));

    auto ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_sign_init(ctx.get()));
    ASSERT_LT(
        0, EVP_PKEY_sign(ctx.get(), nullptr, &siglen, msg.data(), msg.size()));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_PKEY_sign(ctx.get(), sig.data(), &siglen, msg.data(),
                               msg.size()));

    ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_verify_init(ctx.get()));
    ASSERT_LT(0, EVP_PKEY_verify(ctx.get(), sig.data(), sig.size(), msg.data(),
                                 msg.size()));
}

TEST_P(SignatureTest, SignVerifyMessage_SelfTest)
{
    auto param = GetParam();

    auto pkey = ossl::GenerateKeyPair(param.alg, param.group);
    ASSERT_NE(pkey.get(), nullptr);

    std::vector<uint8_t> msg(4096);
    ASSERT_LT(0, RAND_bytes(msg.data(), static_cast<int>(msg.size())));

    size_t siglen = 0;
    std::vector<uint8_t> sig;

    ossl::EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    ASSERT_NE(mdCtx.get(), nullptr);

    auto libctx = ossl::CryptoManager::getInstance().getContext();
    ASSERT_LT(0, EVP_DigestSignInit_ex(mdCtx.get(), nullptr, param.digest,
                                       libctx, nullptr, pkey.get(), nullptr));
    ASSERT_LT(0, EVP_DigestSignUpdate(mdCtx.get(), msg.data(), msg.size()));
    ASSERT_LT(0, EVP_DigestSignFinal(mdCtx.get(), nullptr, &siglen));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_DigestSignFinal(mdCtx.get(), sig.data(), &siglen));

    EVP_MD_CTX_reset(mdCtx.get());
    ASSERT_LT(0, EVP_DigestVerifyInit_ex(mdCtx.get(), nullptr, param.digest,
                                         libctx, nullptr, pkey.get(), nullptr));
    ASSERT_LT(0, EVP_DigestVerifyUpdate(mdCtx.get(), msg.data(), msg.size()));
    ASSERT_LT(0, EVP_DigestVerifyFinal(mdCtx.get(), sig.data(), sig.size()));
}

TEST_P(SignatureTest, SignVerifyMessageDigest_CorruptSignature)
{
    auto param = GetParam();

    auto pkey = ossl::GenerateKeyPair(param.alg, param.group);
    ASSERT_NE(pkey.get(), nullptr);

    auto md = ossl::CryptoManager::getInstance().fetchDigest(param.digest);
    ASSERT_NE(md.get(), nullptr);

    size_t siglen = 0;
    std::vector<uint8_t> msg(EVP_MD_size(md.get()), 0);
    std::vector<uint8_t> sig;

    ASSERT_LT(0, RAND_bytes(msg.data(), static_cast<int>(msg.size())));

    auto ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);

    ASSERT_LT(0, EVP_PKEY_sign_init(ctx.get()));
    ASSERT_LT(
        0, EVP_PKEY_sign(ctx.get(), nullptr, &siglen, msg.data(), msg.size()));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_PKEY_sign(ctx.get(), sig.data(), &siglen, msg.data(),
                               msg.size()));

    sig[0] += 1;

    ctx = ossl::CryptoManager::getInstance().createKeyContext(pkey.get());
    ASSERT_NE(ctx.get(), nullptr);
    ASSERT_LT(0, EVP_PKEY_verify_init(ctx.get()));
    ASSERT_EQ(0, EVP_PKEY_verify(ctx.get(), sig.data(), sig.size(), msg.data(),
                                 msg.size()));
    ERR_clear_error();
}

TEST_P(SignatureTest, SignVerifyMessage_CorruptSignature)
{
    auto param = GetParam();

    auto pkey = ossl::GenerateKeyPair(param.alg, param.group);
    ASSERT_NE(pkey.get(), nullptr);

    std::vector<uint8_t> msg(4096);
    ASSERT_LT(0, RAND_bytes(msg.data(), static_cast<int>(msg.size())));

    size_t siglen = 0;
    std::vector<uint8_t> sig;

    ossl::EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    ASSERT_NE(mdCtx.get(), nullptr);

    auto libctx = ossl::CryptoManager::getInstance().getContext();
    ASSERT_LT(0, EVP_DigestSignInit_ex(mdCtx.get(), nullptr, param.digest,
                                       libctx, nullptr, pkey.get(), nullptr));
    ASSERT_LT(0, EVP_DigestSignUpdate(mdCtx.get(), msg.data(), msg.size()));
    ASSERT_LT(0, EVP_DigestSignFinal(mdCtx.get(), nullptr, &siglen));
    sig.resize(siglen);
    ASSERT_LT(0, EVP_DigestSignFinal(mdCtx.get(), sig.data(), &siglen));

    sig[0] += 1;

    EVP_MD_CTX_reset(mdCtx.get());
    ASSERT_LT(0, EVP_DigestVerifyInit_ex(mdCtx.get(), nullptr, param.digest,
                                         libctx, nullptr, pkey.get(), nullptr));
    ASSERT_LT(0, EVP_DigestVerifyUpdate(mdCtx.get(), msg.data(), msg.size()));
    ASSERT_EQ(0, EVP_DigestVerifyFinal(mdCtx.get(), sig.data(), sig.size()));
    ERR_clear_error();
}

const std::vector<BaseParam> gTestParams = {
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA,
     SN_id_GostR3411_2012_256},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB,
     SN_id_GostR3411_2012_256},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC,
     SN_id_GostR3411_2012_256},
    {SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD,
     SN_id_GostR3411_2012_256},
    {SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetA,
     SN_id_GostR3411_2012_512},
    {SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetB,
     SN_id_GostR3411_2012_512},
    {SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetC,
     SN_id_GostR3411_2012_512}};

INSTANTIATE_TEST_SUITE_P(SignatureTests, SignatureTest,
                         testing::ValuesIn(gTestParams), BaseNameGenerator);