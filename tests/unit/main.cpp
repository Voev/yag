#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/provider.h>

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);
    OSSL_PROVIDER* defaultProv = OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER* prov = OSSL_PROVIDER_load(nullptr, "gostone");
    ERR_print_errors_fp(stderr);

    int ret = RUN_ALL_TESTS();
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(defaultProv);
    return ret;
}
