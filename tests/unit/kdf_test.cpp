#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>

#include <utilities/name_generator.hpp>
#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>

class KdfTreeTest : public testing::Test
{
  public:
    void SetUp()
    {
        kdf.reset(EVP_KDF_fetch(nullptr, "kdf_tree12_256", nullptr));
        ASSERT_NE(kdf.get(), nullptr);
    }

    void TearDown()
    {
        ERR_print_errors_fp(stderr);
    }
    ossl::EvpKdfPtr kdf;
};

static unsigned char secret[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static unsigned char label[] = {0x26, 0xbd, 0xb8, 0x78};

static unsigned char seed[] = {0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};

TEST_F(KdfTreeTest, GetKdfSize)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    ASSERT_GT(EVP_KDF_CTX_get_kdf_size(ctx.get()), 0);
}

TEST_F(KdfTreeTest, FailedToGetParams)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    ASSERT_EQ(EVP_KDF_CTX_get_params(ctx.get(), nullptr), -2);
}

TEST_F(KdfTreeTest, GettableParams)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    ASSERT_NE(EVP_KDF_CTX_gettable_params(ctx.get()), nullptr);
}

TEST_F(KdfTreeTest, SettableParams)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    ASSERT_NE(EVP_KDF_CTX_settable_params(ctx.get()), nullptr);
}

TEST_F(KdfTreeTest, InvalidOutputKeyValue)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[3] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), nullptr, key.size(), nullptr), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), ERR_R_PASSED_NULL_PARAMETER);
}

TEST_F(KdfTreeTest, InvalidOutputKeyLength)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[3] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), 0, nullptr), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_UNSUPPORTED_KEY_SIZE);
}

TEST_F(KdfTreeTest, MissingSecretParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), nullptr), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_MISSING_SECRET);
}

TEST_F(KdfTreeTest, InvalidSecretParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, nullptr, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[3] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), params), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), ERR_R_PASSED_NULL_PARAMETER);
    err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_FAILED_TO_SET_PARAMETER);
}

TEST_F(KdfTreeTest, MissingLabelParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[2] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), nullptr), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_INVALID_DATA);
}

TEST_F(KdfTreeTest, InvalidLabelParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, nullptr, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[3] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), params), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), ERR_R_PASSED_NULL_PARAMETER);
    err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_FAILED_TO_SET_PARAMETER);
}

TEST_F(KdfTreeTest, MissingSeedParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), nullptr), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_MISSING_SEED);
}

TEST_F(KdfTreeTest, InvalidSeedParam)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, nullptr, 0);
    params[3] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> key(64);
    ASSERT_EQ(EVP_KDF_derive(ctx.get(), key.data(), key.size(), params), 0);

    auto err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), ERR_R_PASSED_NULL_PARAMETER);
    err = ERR_get_error();
    ASSERT_EQ(ERR_GET_REASON(err), PROV_R_FAILED_TO_SET_PARAMETER);
}

TEST_F(KdfTreeTest, SuccessfullDerive)
{
    ossl::EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(ctx.get(), nullptr);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret,
                                                  sizeof(secret));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label,
                                                  sizeof(label));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
                                                  sizeof(seed));
    params[3] = OSSL_PARAM_construct_end();
    ASSERT_GT(EVP_KDF_CTX_set_params(ctx.get(), params), 0);

    std::vector<uint8_t> key(64);
    ASSERT_GT(EVP_KDF_derive(ctx.get(), key.data(), key.size(), nullptr), 0);
}
