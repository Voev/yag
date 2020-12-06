#include <vector>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <utilities/ossl_pointers.hpp>
#include <utilities/name_generator.hpp>

static 
std::string NameGenerator( const testing::TestParamInfo< const char* >& info )
{
    std::string name = info.param;
    NameGeneratorFiltering( name );
    return name;
}

class DigestTest : public testing::TestWithParam< const char* >
{
public:
    void SetUp()
    {}

    void TearDown()
    {
        ERR_print_errors_fp( stderr );
    }

protected:
    OSSL_PROVIDER* prov_ = nullptr;
};

TEST_P( DigestTest, DigestInit )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );
}

TEST_P( DigestTest, DigestUpdate )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestUpdate( ctx.get(), block.data(), block.size() ) );
}

TEST_P( DigestTest, DigestUpdateNullArgument )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_EQ( 0, EVP_DigestUpdate( ctx.get(), nullptr, block.size() ) );
    ERR_pop_to_mark();
}

TEST_P( DigestTest, DigestUpdateZeroLength )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestUpdate( ctx.get(), block.data(), 0 ) );
}

TEST_P( DigestTest, DigestFinal )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestUpdate( ctx.get(), block.data(), block.size() ) );

    std::vector< uint8_t > digest( EVP_MD_size( md.get() ) );
    unsigned int digestSize = 0;
    ASSERT_LT( 0, EVP_DigestFinal_ex( ctx.get(), digest.data(), &digestSize ) );
    ASSERT_EQ( digestSize, EVP_MD_size( md.get() ) );
}

TEST_P( DigestTest, DigestFinalNullArgument )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestUpdate( ctx.get(), block.data(), block.size() ) );

    unsigned int digestSize = 0;
    ASSERT_EQ( 0, EVP_DigestFinal_ex( ctx.get(), nullptr, &digestSize ) );
    ERR_pop_to_mark();
}

TEST_P( DigestTest, DigestFinalZeroLength )
{
    ossl::EvpMdPtr md( EVP_MD_fetch( nullptr, GetParam(),
                                     nullptr ) );
    ASSERT_NE( md.get(), nullptr );

    ossl::EvpMdCtxPtr ctx( EVP_MD_CTX_new() );
    ASSERT_NE( ctx.get(), nullptr );
    ASSERT_LT( 0, EVP_DigestInit( ctx.get(), md.get() ) );

    std::vector< uint8_t > block( EVP_MD_block_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestUpdate( ctx.get(), block.data(), block.size() ) );

    std::vector< uint8_t > digest( EVP_MD_size( md.get() ) );
    ASSERT_LT( 0, EVP_DigestFinal_ex( ctx.get(), digest.data(), nullptr ) );
}

INSTANTIATE_TEST_SUITE_P(
    DigestTests,
    DigestTest,
    testing::Values(
        SN_id_GostR3411_2012_256,
        SN_id_GostR3411_2012_512
    ),
    NameGenerator
);
