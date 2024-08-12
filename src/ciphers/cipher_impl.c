#include <openssl/core_dispatch.h>
#include <yag/common.h>
#include <yag/implementations.h>
#include <yag/ciphers/cipher_common.h>
#include <yag/ciphers/kuznyechik_funcs.h>

#define IMPLEMENT_KUZNYECHIK_CIPHER(mode)                                      \
    const OSSL_DISPATCH gKuznyechik##mode##Funcs[] = {                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, FUNC_PTR(GsCipherEncryptInit)},        \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, FUNC_PTR(GsCipherDecryptInit)},        \
        {OSSL_FUNC_CIPHER_NEWCTX, FUNC_PTR(GsKuznyechik##mode##NewCtx)},       \
        {OSSL_FUNC_CIPHER_DUPCTX, FUNC_PTR(GsCipherDupCtx)},                   \
        {OSSL_FUNC_CIPHER_FREECTX, FUNC_PTR(GsKuznyechikFreeCtx)},             \
        {OSSL_FUNC_CIPHER_UPDATE, FUNC_PTR(GsCipherBlockUpdate)},              \
        {OSSL_FUNC_CIPHER_FINAL, FUNC_PTR(GsCipherBlockFinal)},                \
        {OSSL_FUNC_CIPHER_CIPHER, FUNC_PTR(GsCipherCipher)},                   \
        {OSSL_FUNC_CIPHER_GET_PARAMS,                                          \
         FUNC_PTR(GsKuznyechik##mode##GetParams)},                             \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                     \
         FUNC_PTR(GsKuznyechikGettableParams)},                                \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, FUNC_PTR(GsCipherSetCtxParams)},     \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                 \
         FUNC_PTR(GsKuznyechikSettableCtxParams)},                             \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                      \
         FUNC_PTR(GsKuznyechikGettableCtxParams)},                             \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                 \
         FUNC_PTR(GsKuznyechikGettableCtxParams)},                             \
        {0, NULL}};

IMPLEMENT_KUZNYECHIK_CIPHER(ECB)
