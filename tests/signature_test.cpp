#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>
#include <utilities/name_generator.hpp>

using BaseParam = std::pair< const char*, const char* >;

static
std::string BaseNameGenerator( const testing::TestParamInfo< BaseParam >& info )
{
    auto param  = info.param;
    std::string name = param.second;
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

TEST_P( SignatureTest, SignMessageDigest )
{
    auto param = GetParam();
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr,
                                                         param.first, nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_keygen_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         param.second ) );

    EVP_PKEY* generated = nullptr;
    ASSERT_LT( 0, EVP_PKEY_keygen( ctx.get(), &generated ) );
    ossl::EvpPkeyPtr pkey( generated );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::EvpPkeyCtxPtr sctx( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( sctx.get(), nullptr );
    
    ASSERT_LT( 0, EVP_PKEY_sign_init( sctx.get() ) );
    EVP_MD* md = EVP_MD_fetch( nullptr, "md_gost12_256", nullptr );

    ASSERT_LT( 0, EVP_PKEY_CTX_set_signature_md( sctx.get(), md ) );
    EVP_MD_free( md );


    std::vector< uint8_t > sig( 64 );
    size_t siglen = 0;

    std::vector< uint8_t > msg( 32, 1 );

    ASSERT_LT( 0, EVP_PKEY_sign( sctx.get(), sig.data(), &siglen, msg.data(), msg.size() ) );
}

TEST_P( SignatureTest, SignAndVerifyMessageDigest )
{
    auto param = GetParam();
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr,
                                                         param.first, nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_keygen_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         param.second ) );

    EVP_PKEY* generated = nullptr;
    ASSERT_LT( 0, EVP_PKEY_keygen( ctx.get(), &generated ) );
    ossl::EvpPkeyPtr pkey( generated );
    ASSERT_NE( pkey.get(), nullptr );

    size_t siglen = 0;
    std::vector< uint8_t > sig( 64 );
    std::vector< uint8_t > msg( 32, 1 );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_sign_init( ctx.get() ) );
    /*EVP_MD* md = EVP_MD_fetch( nullptr, "md_gost12_256", nullptr );
    ASSERT_LT( 0, EVP_PKEY_CTX_set_signature_md( ctx.get(), md ) );
    EVP_MD_free( md );*/
    ASSERT_LT( 0, EVP_PKEY_sign( ctx.get(), sig.data(), &siglen, msg.data(), msg.size() ) );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_verify_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_verify( ctx.get(), sig.data(), sig.size(), msg.data(), msg.size() ) );
}

const std::vector< BaseParam > gTestParams =
{
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD }
};

INSTANTIATE_TEST_SUITE_P(
    SignatureTests,
    SignatureTest,
    testing::ValuesIn( gTestParams ),
    BaseNameGenerator
);
