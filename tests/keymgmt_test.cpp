#include <vector>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <utilities/ossl_pointers.hpp>
#include "global.hpp"

class KeymgmtTest : public testing::TestWithParam< const char* >
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
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( ossl::LibCtx::Get0(),
                                                         GetParam(), nullptr ) );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_PKEY_keygen_init( ctx.get() ) );
    ASSERT_LT( 0, EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         SN_id_tc26_gost_3410_2012_256_paramSetA ) );

    EVP_PKEY* generated = nullptr;
    ASSERT_LT( 0, EVP_PKEY_keygen( ctx.get(), &generated ) );
    ossl::EvpPkeyPtr pkey( generated );
    ASSERT_NE( pkey.get(), nullptr );

    BIO* b = BIO_new_fp( stderr, BIO_NOCLOSE );
    ASSERT_LT( 0, i2d_PrivateKey_bio( b, pkey.get() ) );
    BIO_free( b );
}

INSTANTIATE_TEST_SUITE_P(
    KeymgmtTests,
    KeymgmtTest,
    testing::Values(
        SN_id_GostR3410_2012_256//,
        //SN_id_GostR3410_2012_512
    )
);
