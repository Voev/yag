#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>
#include <utilities/name_generator.hpp>

struct BaseParam
{
    const char* alg;
    const char* group;
    size_t msgSize;
    size_t sigSize;
}; 

static
std::string BaseNameGenerator( const testing::TestParamInfo< BaseParam >& info )
{
    auto param  = info.param;
    std::string name = param.group;
    NameGeneratorFiltering( name ); 
    return name;
}

class SignatureTest 
    : public testing::TestWithParam< BaseParam >
{
public:
    void SetUp()
    {}

    void TearDown()
    {
        ERR_print_errors_fp( stderr );
    }
};

TEST_P( SignatureTest, SignAndVerifyEmptyMessageDigest )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.alg, param.group ) );
    ASSERT_NE( pkey.get(), nullptr );

    size_t siglen = 0;
    std::vector< uint8_t > sig( param.sigSize );
    std::vector< uint8_t > msg( param.msgSize, 0 );

    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_sign_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_sign( ctx.get(), sig.data(), &siglen, msg.data(), msg.size() ) );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_verify_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_verify( ctx.get(), sig.data(), sig.size(), msg.data(), msg.size() ) );
}

TEST_P( SignatureTest, SignAndVerifyMessageDigest )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.alg, param.group ) );
    ASSERT_NE( pkey.get(), nullptr );

    size_t siglen = 0;
    std::vector< uint8_t > sig( param.sigSize );
    std::vector< uint8_t > msg( param.msgSize );
    ASSERT_LT( 0, RAND_bytes( msg.data(), static_cast< int >( msg.size() ) ) );

    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_sign_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_sign( ctx.get(), sig.data(), &siglen, msg.data(), msg.size() ) );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_verify_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_verify( ctx.get(), sig.data(), sig.size(), msg.data(), msg.size() ) );
}

TEST_P( SignatureTest, OneCorruptedByte )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.alg, param.group ) );
    ASSERT_NE( pkey.get(), nullptr );

    size_t siglen = 0;
    std::vector< uint8_t > sig( param.sigSize );
    std::vector< uint8_t > msg( param.msgSize );
    ASSERT_LT( 0, RAND_bytes( msg.data(), static_cast< int >( msg.size() ) ) );

    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_sign_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_sign( ctx.get(), sig.data(), &siglen, msg.data(), msg.size() ) );

    sig[ 0 ] += 1;

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_verify_init( ctx.get() ) );
    ASSERT_EQ( 0, EVP_PKEY_verify( ctx.get(), sig.data(), sig.size(), msg.data(), msg.size() ) );
    ERR_clear_error();
}

const std::vector< BaseParam > gTestParams =
{
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA, 32, 64  },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB, 32, 64  },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC, 32, 64  },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD, 32, 64  },
    { SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetA, 64, 128 },
    { SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetB, 64, 128 },
    { SN_id_GostR3410_2012_512, SN_id_tc26_gost_3410_2012_512_paramSetC, 64, 128 }
};

INSTANTIATE_TEST_SUITE_P(
    SignatureTests,
    SignatureTest,
    testing::ValuesIn( gTestParams ),
    BaseNameGenerator
);
