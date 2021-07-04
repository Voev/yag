#include <gtest/gtest.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <vector>

#include <utilities/name_generator.hpp>
#include <utilities/ossl_pointers.hpp>
#include <utilities/ossl_tool.hpp>

class DecodeTest : public testing::Test
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

const unsigned char key[] = {
    0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x1f, 0x06, 0x08, 0x2a, 0x85,
    0x03, 0x07, 0x01, 0x01, 0x01, 0x01, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x08, 0x2a, 0x85, 0x03,
    0x07, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x5c, 0xf6, 0x35, 0x9e,
    0x00, 0x4f, 0x13, 0x1e, 0xa4, 0xfd, 0x72, 0x7e, 0x63, 0xfc, 0xaf,
    0x92, 0xa1, 0xa2, 0x20, 0x19, 0x58, 0x8e, 0x06, 0x54, 0x6f, 0x7c,
    0xa0, 0x1e, 0x2b, 0xf9, 0x25, 0xbe, 0x0a};
unsigned int key_len = 73;

TEST_F(DecodeTest, DecodePrivateKey)
{

    EVP_PKEY* pkey = nullptr;
    BIO* b = BIO_new_mem_buf(key, key_len);
    ASSERT_NE(b, nullptr);
    OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, "DER", NULL, "gost2012_256", 0, nullptr, nullptr);
    ASSERT_NE(dctx, nullptr);
    ASSERT_LT(0, OSSL_DECODER_from_bio(dctx, b));
    BIO_free(b);
    OSSL_DECODER_CTX_free(dctx);
}
