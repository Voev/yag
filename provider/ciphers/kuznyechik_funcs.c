#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <gostone/provider_ctx.h>
#include <gostone/ciphers/kuznyechik_core.h>
#include <gostone/ciphers/kuznyechik_defs.h>
#include <gostone/ciphers/kuznyechik_funcs.h>

DEFINE_KUZNYECHIK_CIPHER_NEW_CTX(ECB, 0, 256, 128, 128)
DEFINE_KUZNYECHIK_CIPHER_GET_PARAMS(ECB, 0, 256, 128, 128)

const OSSL_PARAM* GsKuznyechikGettableParams(ossl_unused void* provCtx)
{
    CIPHER_DEFAULT_GETTABLE_PARAMS_START(Kuznyechik)
    CIPHER_DEFAULT_GETTABLE_PARAMS_END(Kuznyechik)
    return gKuznyechikKnownGettableParams;
}

void GsKuznyechikFreeCtx(void* vctx)
{
    GsKuznyechikCtx* ctx = (GsKuznyechikCtx*)vctx;
    ossl_cipher_generic_reset_ctx((GsCipherCtx*)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
