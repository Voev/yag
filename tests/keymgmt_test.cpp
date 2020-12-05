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
#include "global.hpp"

using BaseParam = std::pair< const char*, const char* >;

static
std::string BaseNameGenerator( const testing::TestParamInfo< BaseParam >& info )
{
    auto param  = info.param;
    std::string name = param.second;
    NameGeneratorFiltering( name ); 
    return name;
}

class KeymgmtTest 
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

TEST_P( KeymgmtTest, GeneratePrivateKeyWithChecking )
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

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_private_check( ctx.get() ) );
}

TEST_P( KeymgmtTest, GeneratePublicKeyWithChecking )
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
    
    X509_PUBKEY* pubkey = nullptr;
    ASSERT_LT( 0, X509_PUBKEY_set( &pubkey, pkey.get() ) );
    ossl::X509PubKeyPtr pub( pubkey );
    ASSERT_NE( pub.get(), nullptr );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, 
                                           X509_PUBKEY_get0( pub.get() ), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_public_check( ctx.get() ) );
}

TEST_P( KeymgmtTest, PairwiseCheck )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_pairwise_check( ctx.get() ) );
}

TEST_P( KeymgmtTest, GenerateKeyParametersWithChecking )
{
    auto param = GetParam();
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr,
                                                         param.first, nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_paramgen_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         param.second ) );

    EVP_PKEY* generated = nullptr;
    ASSERT_LT( 0, EVP_PKEY_paramgen( ctx.get(), &generated ) );
    ossl::EvpPkeyPtr pkey( generated );
    ASSERT_NE( pkey.get(), nullptr );

    ctx.reset( EVP_PKEY_CTX_new_from_pkey( nullptr, pkey.get(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_param_check( ctx.get() ) );
}

TEST_P( KeymgmtTest, ParamMissing )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    ASSERT_EQ( 0, EVP_PKEY_missing_parameters( pkey.get() ) );
}

const std::vector< BaseParam > gTestParams =
{
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD }
};

INSTANTIATE_TEST_SUITE_P(
    KeymgmtTests,
    KeymgmtTest,
    testing::ValuesIn( gTestParams ),
    BaseNameGenerator
);

using ComparisonParam = std::tuple< BaseParam, BaseParam >;

static
std::string ComparisonNameGenerator( const testing::TestParamInfo< ComparisonParam >& info )
{
    std::stringstream ss;
    auto firstParam  = std::get< 0 >( info.param );
    auto secondParam = std::get< 1 >( info.param );
    std::string first = firstParam.second;
    std::string second = secondParam.second;
    NameGeneratorFiltering( first ); 
    NameGeneratorFiltering( second );
    return first + "_vs_" + second;
}

class KeymgmtComparisonTest 
    : public testing::TestWithParam< ComparisonParam >
{
public:
    void SetUp()
    {}

    void TearDown()
    {
        ERR_print_errors_fp( stderr );
    }
};

TEST_P( KeymgmtComparisonTest, CompareKeyParameters )
{
    auto param = GetParam();
    auto firstParam = std::get< 0 >( param );
    auto secondParam = std::get< 1 >( param );

    ossl::EvpPkeyPtr firstKey( ossl::GenerateKeyPair( firstParam.first, firstParam.second ) );
    ASSERT_NE( firstKey.get(), nullptr );

    ossl::EvpPkeyPtr secondKey( ossl::GenerateKeyPair( secondParam.first, secondParam.second ) );
    ASSERT_NE( secondKey.get(), nullptr );

    int ret = strcmp( firstParam.second, secondParam.second ) ? 0 : 1;
    ASSERT_EQ( ret, EVP_PKEY_parameters_eq( firstKey.get(), secondKey.get() ) );
}

TEST_P( KeymgmtComparisonTest, CompareKeys )
{
    auto param = GetParam();
    auto firstParam = std::get< 0 >( param );
    auto secondParam = std::get< 1 >( param );

    ossl::EvpPkeyPtr firstKey( ossl::GenerateKeyPair( firstParam.first, firstParam.second ) );
    ASSERT_NE( firstKey.get(), nullptr );

    ossl::EvpPkeyPtr secondKey( ossl::GenerateKeyPair( secondParam.first, secondParam.second ) );
    ASSERT_NE( secondKey.get(), nullptr );

    ASSERT_EQ( 0, EVP_PKEY_eq( firstKey.get(), secondKey.get() ) );
    ERR_clear_error();
}

INSTANTIATE_TEST_SUITE_P(
    KeymgmtComparisonTests,
    KeymgmtComparisonTest,
    testing::Combine(
        testing::ValuesIn( gTestParams ),
        testing::ValuesIn( gTestParams )
    ),
    ComparisonNameGenerator
);
