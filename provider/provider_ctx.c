#include <openssl/core.h>
#include <openssl/crypto.h>
#include <gostone/provider_ctx.h>

struct gs_prov_ctx_st
{
    const OSSL_CORE_HANDLE* handle;
    OSSL_LIB_CTX* libCtx;
};

GsProvCtx* GsProvCtxNew( void )
{
    return OPENSSL_zalloc( sizeof( GsProvCtx ) );
}

void GsProvCtxFree( GsProvCtx* ctx )
{
    OPENSSL_free( ctx );
}

void GsProvCtxSet0LibCtx( GsProvCtx* ctx, OSSL_LIB_CTX* libCtx )
{
    if( ctx )
    {
        ctx->libCtx = libCtx;
    }
}

void GsProvCtxSet0Handle( GsProvCtx* ctx, const OSSL_CORE_HANDLE* handle )
{
    if( ctx )
    {
        ctx->handle = handle;
    }
}

OSSL_LIB_CTX* GsProvCtxGet0LibCtx( GsProvCtx* ctx )
{
    return ctx ? ctx->libCtx : NULL;
}

const OSSL_CORE_HANDLE* GsProvCtxGet0Handle( GsProvCtx* ctx )
{
    return ctx ? ctx->handle : NULL;
}
