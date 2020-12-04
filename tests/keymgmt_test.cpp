#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <utilities/ossl_pointers.hpp>
#include "global.hpp"

using TestParam = std::pair< const char*, const char* >;

class KeymgmtTest 
    : public testing::TestWithParam< TestParam >
{
public:
    void SetUp()
    {}

    void TearDown()
    {
        ERR_print_errors_fp( stderr );
    }

protected:
    OSSL_PROVIDER* defaultProv_ = nullptr;
    OSSL_PROVIDER* prov_ = nullptr;
};

EVP_PKEY* GenerateKeyPair( const char* alg, const char* group )
{
    EVP_PKEY* pkey = nullptr;
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr, alg, nullptr ) );
    if( !ctx.get() ||
        !EVP_PKEY_keygen_init( ctx.get() ) ||
        !EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group ) ||
        !EVP_PKEY_keygen( ctx.get(), &pkey ) )
    {
        return nullptr;
    }
    return pkey;
}

EVP_PKEY* GenerateParameters( const char* alg, const char* group )
{
    EVP_PKEY* pkey = nullptr;
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr, alg, nullptr ) );
    if( !ctx.get() ||
        !EVP_PKEY_paramgen_init( ctx.get() ) ||
        !EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group ) ||
        !EVP_PKEY_paramgen( ctx.get(), &pkey ) )
    {
        return nullptr;
    }
    return pkey;
}

TEST_P( KeymgmtTest, PrivateKey )
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
}

TEST_P( KeymgmtTest, PublicKey )
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
    X509_PUBKEY_set( &pubkey, pkey.get() );
    ossl::X509PubKeyPtr pub( pubkey );
    ASSERT_NE( pub.get(), nullptr );
}

TEST_P( KeymgmtTest, KeyParameters )
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
}

TEST_P( KeymgmtTest, ParamMissing )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    ASSERT_EQ( 0, EVP_PKEY_missing_parameters( pkey.get() ) );
}

TEST_P( KeymgmtTest, PrintPrivateKey )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_private( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( KeymgmtTest, PrintPublicKey )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_public( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( KeymgmtTest, PrintParameters )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );

    ossl::BioPtr out( BIO_new( BIO_s_null() ) );
    ASSERT_LT( 0, EVP_PKEY_print_params( out.get(), pkey.get(), 0, nullptr ) );
}

TEST_P( KeymgmtTest, EncodePrivateKey )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_PKCS8PrivateKeyInfo_bio( bio.get(), pkey.get() ) );
}

TEST_P( KeymgmtTest, EncodePublicKey )
{
    auto param = GetParam();
    ossl::EvpPkeyPtr pkey( GenerateKeyPair( param.first, param.second ) );
    ASSERT_NE( pkey.get(), nullptr );
    
    X509_PUBKEY* pubkey = nullptr;
    X509_PUBKEY_set( &pubkey, pkey.get() );
    ossl::X509PubKeyPtr pub( pubkey );
    ASSERT_NE( pub.get(), nullptr );

    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_X509_PUBKEY_bio( bio.get(), pub.get() ) );
}

TEST_P( KeymgmtTest, EncodeKeyParameters )
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
    
    ossl::BioPtr bio( BIO_new( BIO_s_mem() ) );
    ASSERT_NE( bio.get(), nullptr );
    ASSERT_LT( 0, i2d_KeyParams_bio( bio.get(), pkey.get() ) );
}

const std::vector< TestParam > gTestParams =
{
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetA },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetB },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetC },
    { SN_id_GostR3410_2012_256, SN_id_tc26_gost_3410_2012_256_paramSetD }
};

INSTANTIATE_TEST_SUITE_P(
    KeymgmtTests,
    KeymgmtTest,
    testing::ValuesIn( gTestParams )
);
