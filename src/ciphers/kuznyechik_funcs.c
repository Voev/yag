#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <yag/provider_ctx.h>
#include <yag/ciphers/kuznyechik_core.h>
#include <yag/ciphers/kuznyechik_defs.h>
#include <yag/ciphers/kuznyechik_funcs.h>

const OSSL_PARAM* GsKuznyechikGettableParams(ossl_unused void* provCtx)
{
    CIPHER_DEFAULT_GETTABLE_PARAMS_START(Kuznyechik)
    CIPHER_DEFAULT_GETTABLE_PARAMS_END(Kuznyechik)
    return gKuznyechikKnownGettableParams;
}

const OSSL_PARAM* GsKuznyechikSettableCtxParams(ossl_unused void* cctx,
                                                ossl_unused void* provCtx)
{
    CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(Kuznyechik)
    CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(Kuznyechik)
    return gKuznyechikKnownSettableCtxParams;
}

const OSSL_PARAM* GsKuznyechikGettableCtxParams(ossl_unused void* cctx,
                                                ossl_unused void* provCtx)
{
    CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(Kuznyechik)
    CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(Kuznyechik)
    return gKuznyechikKnownGettableCtxParams;
}

void GsKuznyechikFreeCtx(void* vctx)
{
    GsKuznyechikCtx* ctx = (GsKuznyechikCtx*)vctx;
    GsCipherCtxReset((GsCipherCtx*)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

int GsKuznyechikInitKey(GsCipherCtx* ctx, const unsigned char* key,
                        size_t keylen)
{
    GsKuznyechikCtx* kctx = (GsKuznyechikCtx*)ctx;
    (void)kctx;
    (void)key;
    (void)keylen;
    return 1;
}

void GsKuznyechikCopyCtx(GsCipherCtx* dst, const GsCipherCtx* src)
{
    GsKuznyechikCtx* sctx = (GsKuznyechikCtx*)src;
    GsKuznyechikCtx* dctx = (GsKuznyechikCtx*)dst;

    *dctx = *sctx;
    dst->ks = &dctx->base.ks;
}

int GsKuznyechikECBCipher(GsCipherCtx* ctx, unsigned char* out,
                          const unsigned char* in, size_t len)
{
    (void)ctx;
    (void)out;
    (void)in;
    (void)len;
    return 1;
}

DEFINE_CIPHER_SPEC(Kuznyechik, ECB)

DEFINE_KUZNYECHIK_CIPHER_NEW_CTX(ECB, 0, 256, 128, 128)
DEFINE_KUZNYECHIK_CIPHER_GET_PARAMS(ECB, 0, 256, 128, 128)
