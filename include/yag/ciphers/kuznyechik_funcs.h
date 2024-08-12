#pragma once
#include <openssl/core_dispatch.h>
#include <yag/ciphers/cipher_common.h>

typedef struct gs_kuznyechik_ctx_st
{
    GsCipherCtx base; /* Must be first */
    unsigned char ks;
} GsKuznyechikCtx;

#define DEFINE_CIPHER_SPEC(type, mode)                                         \
    static const GsCipherSpec g##type##Cipher##mode = {                        \
        Gs##type##InitKey, Gs##type##mode##Cipher, Gs##type##CopyCtx};         \
    const GsCipherSpec* Gs##type##_##mode(void)                                \
    {                                                                          \
        return &g##type##Cipher##mode;                                         \
    }

const GsCipherSpec* GsKuznyechikCipherECB(void);
const GsCipherSpec* GsKuznyechikCipherCTR(void);

OSSL_FUNC_cipher_freectx_fn GsKuznyechikFreeCtx;
OSSL_FUNC_cipher_gettable_params_fn GsKuznyechikGettableParams;
OSSL_FUNC_cipher_gettable_ctx_params_fn GsKuznyechikGettableCtxParams;
OSSL_FUNC_cipher_settable_ctx_params_fn GsKuznyechikSettableCtxParams;

#define DECLARE_KUZNYECHIK_CIPHER_NEW_CTX(mode)                                \
    OSSL_FUNC_cipher_newctx_fn GsKuznyechik##mode##NewCtx;

#define DECLARE_KUZNYECHIK_CIPHER_GET_PARAMS(mode)                             \
    OSSL_FUNC_cipher_get_params_fn GsKuznyechik##mode##GetParams;

#define DEFINE_KUZNYECHIK_CIPHER_NEW_CTX(mode, flags, keyBits, blockBits,      \
                                         ivBits)                               \
    void* GsKuznyechik##mode##NewCtx(ossl_unused void* provCtx)                \
    {                                                                          \
        GsKuznyechikCtx* ctx = OPENSSL_zalloc(sizeof(*ctx));                   \
        if (NULL != ctx)                                                       \
        {                                                                      \
            GsCipherCtxInit(INTERPRET_AS_CIPHER_CTX(ctx), keyBits, blockBits,  \
                            ivBits, EVP_CIPH_##mode##_MODE, flags,             \
                            GsKuznyechik_##mode(), provCtx);                   \
        }                                                                      \
        return ctx;                                                            \
    }

#define DEFINE_KUZNYECHIK_CIPHER_GET_PARAMS(mode, flags, keyBits, blockBits,   \
                                            ivBits)                            \
    int GsKuznyechik##mode##GetParams(OSSL_PARAM params[])                     \
    {                                                                          \
        return GsCipherGetParams(params, EVP_CIPH_##mode##_MODE, flags,        \
                                 keyBits, blockBits, ivBits);                  \
    }

DECLARE_KUZNYECHIK_CIPHER_NEW_CTX(ECB)
DECLARE_KUZNYECHIK_CIPHER_GET_PARAMS(ECB)

// DECLARE_KUZNYECHIK_CIPHER_NEW_CTX(CTR)
// DECLARE_KUZNYECHIK_CIPHER_GET_PARAMS(CTR)
