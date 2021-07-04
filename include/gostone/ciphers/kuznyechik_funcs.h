#pragma once
#include <openssl/core_dispatch.h>
#include <gostone/ciphers/cipher_common.h>

typedef struct gs_kuznyechik_ctx_st
{
    GsCipherCtx base; /* Must be first */
    unsigned char ks;
} GsKuznyechikCtx;

const GsCipherSpec* GsKuznyechikCipherECB(void);
const GsCipherSpec* GsKuznyechikCipherCTR(void);

OSSL_FUNC_cipher_freectx_fn GsKuznyechikFreeCtx;
OSSL_FUNC_cipher_gettable_params_fn GsKuznyechikGettableParams;

#define DECLARE_KUZNYECHIK_CIPHER_NEW_CTX(mode)                                \
    OSSL_FUNC_cipher_newctx_fn GsKuznyechik##mode##NewCtx;

#define DECLARE_KUZNYECHIK_CIPHER_GET_PARAMS(mode)                             \
    OSSL_FUNC_cipher_get_params_fn GsKuznyechik##mode##GetParams;

#define DEFINE_KUZNYECHIK_CIPHER_NEW_CTX(mode, flags, keyBits, blockBits,      \
                                         ivBits)                               \
    void* GsKuznyechik##mode##NewCtx(void* provCtx)                            \
    {                                                                          \
        GsKuznyechikCtx* ctx = OPENSSL_zalloc(sizeof(*ctx));                   \
        if (NULL != ctx)                                                       \
        {                                                                      \
            GsCipherCtxInit(INTERPRET_AS_CIPHER_CTX(ctx), keyBits, blockBits,  \
                            ivBits, EVP_CIPH_##mode##_MODE, flags,             \
                            GsKuznyechik##mode());                             \
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

DECLARE_KUZNYECHIK_CIPHER_NEW_CTX(CTR)
DECLARE_KUZNYECHIK_CIPHER_GET_PARAMS(CTR)
