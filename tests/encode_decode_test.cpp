#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
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

class EncodeDecodeTest 
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

TEST_P( EncodeDecodeTest, EncodePrivateKeyToText )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_private( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( EncodeDecodeTest, EncodePublicKeyToText )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_public( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( EncodeDecodeTest, EncodeParametersToText )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateParameters( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_params( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( EncodeDecodeTest, EncodePrivateKeyToDer )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_PKCS8PrivateKeyInfo_bio( bio.get(), pkey.get() ) );
}

TEST_P( EncodeDecodeTest, EncodePrivateKeyToPem )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, PEM_write_bio_PrivateKey( bio.get(), pkey.get(), 
                                            nullptr, nullptr, 0, 
                                            nullptr, nullptr ) );
}

TEST_P( EncodeDecodeTest, EncodePublicKeyToDer )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    X509_PUBKEY* pubkey = nullptr;
    X509_PUBKEY_set( &pubkey, pkey.get() );
    ossl::X509PubKeyPtr pub( pubkey );
    ASSERT_NE( pub.get(), nullptr );

    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_X509_PUBKEY_bio( bio.get(), pub.get() ) );
}

TEST_P( EncodeDecodeTest, EncodePublicKeyToPem )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    X509_PUBKEY* pubkey = nullptr;
    X509_PUBKEY_set( &pubkey, pkey.get() );
    ossl::X509PubKeyPtr pub( pubkey );
    ASSERT_NE( pub.get(), nullptr );

    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, PEM_write_bio_X509_PUBKEY( bio.get(), pub.get() ) );
}

TEST_P( EncodeDecodeTest, EncodeKeyParametersToDer )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( ossl::GenerateParameters( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_KeyParams_bio( bio.get(), pkey.get() ) );
}

const std::vector< BaseParam > gTestParams =
{
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD }
};

INSTANTIATE_TEST_SUITE_P(
    EncodeDecodeTests,
    EncodeDecodeTest,
    testing::ValuesIn( gTestParams ),
    BaseNameGenerator
);