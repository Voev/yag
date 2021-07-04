#include <openssl/core_dispatch.h>
#include <gostone/common.h>
#include <gostone/ciphers/cipher_common.h>
#include <gostone/ciphers/kuznyechik_funcs.h>

#define IMPLEMENT_KUZNYECHIK_CIPHER(mode)                                      \
    const OSSL_DISPATCH gKuznyechik##mode##Funcs[] = {                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, FUNC_PTR(GsCipherEncryptInit)},        \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, FUNC_PTR(GsCipherDecryptInit)},        \
        {OSSL_FUNC_CIPHER_NEWCTX, FUNC_PTR(GsKuznyechik##mode##NewCtx)},       \
        {OSSL_FUNC_CIPHER_DUPCTX, FUNC_PTR(GsCipherDupCtx)},                   \
        {OSSL_FUNC_CIPHER_FREECTX, FUNC_PTR(GsKuznyechikFreeCtx)},             \
        {OSSL_FUNC_CIPHER_GET_PARAMS,                                          \
         FUNC_PTR(GsKuznyechik##mode##GetParams)},                             \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                     \
         FUNC_PTR(GsKuznyechik##mode##GettableParams)},                        \
        {0, NULL}}

/*
        {OSSL_FUNC_CIPHER_UPDATE, \
         FUNC_PTR(ossl_cipher_generic_##block##_update},                \
        {OSSL_FUNC_CIPHER_FINAL, \
         FUNC_PTR(ossl_cipher_generic_##block##_final},                 \
        {OSSL_FUNC_CIPHER_CIPHER, FUNC_PTR(ossl_cipher_generic_cipher}, \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, FUNC_PTR(des_get_ctx_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, \
         FUNC_PTR(des_gettable_ctx_params},                             \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, \
         FUNC_PTR(ossl_cipher_generic_set_ctx_params},                  \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, \
         FUNC_PTR(ossl_cipher_generic_settable_ctx_params},             \
        {0, NULL}}
*/
IMPLEMENT_KUZNYECHIK_CIPHER(ECB)
