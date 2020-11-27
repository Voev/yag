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
    {
        prov_ = OSSL_PROVIDER_load( ossl::LibCtx::Get0(), "gostone" );
        ASSERT_NE( prov_, nullptr );
    }
    void TearDown()
    {
        ERR_print_errors_fp( stderr );
        OSSL_PROVIDER_unload( prov_ );
    }

protected:
    OSSL_PROVIDER* prov_ = nullptr;
};

TEST_P( KeymgmtTest, Init )
{
    auto param = GetParam();
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( ossl::LibCtx::Get0(),
                                                         param.first, nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_keygen_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         param.second ) );

    EVP_PKEY* generated = nullptr;
    ASSERT_LT( 0, EVP_PKEY_keygen( ctx.get(), &generated ) );
    ossl::EvpPkeyPtr pkey( generated );
    ASSERT_NE( pkey.get(), nullptr );
    
    //EC_KEY_print_fp( stderr, (EC_KEY*)EVP_PKEY_get0( pkey.get()), 0 );
   // BIO* b = BIO_new_fp( stderr, BIO_NOCLOSE );
   //  ASSERT_LT( 0, i2d_PrivateKey_bio( b, pkey.get() ) );
   //  BIO_free( b );
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
