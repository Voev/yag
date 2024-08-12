#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/provider.h>

int main(int argc, char* argv[])
{
    if (argc < 2)
        return EXIT_FAILURE;
    OSSL_PROVIDER_set_default_search_path(nullptr, argv[1]);
    
    testing::InitGoogleTest(&argc, argv);

    OSSL_PROVIDER* defaultProv = OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER* prov = OSSL_PROVIDER_load(nullptr, "gostone");
    if (!prov) {
       ERR_print_errors_fp(stderr);
       return EXIT_FAILURE;
    }

    int ret = RUN_ALL_TESTS();

    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(defaultProv);

    return ret;
}
