#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <gostone/provider_ctx.h>

struct gs_prov_ctx_st
{
    const OSSL_CORE_HANDLE* handle;
    OSSL_LIB_CTX* libCtx;
    BIO_METHOD* coreBioMeth;
};

GsProvCtx* GsProvCtxNew( void )
{
    return OPENSSL_zalloc( sizeof( GsProvCtx ) );
}

void GsProvCtxFree( GsProvCtx* ctx )
{
    if( ctx )
    {
        BIO_meth_free( ctx->coreBioMeth );
        OPENSSL_clear_free( ctx, sizeof( *ctx ) );
    }
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

void GsProvCtxSet0CoreBioMeth( GsProvCtx* ctx, BIO_METHOD* coreBioMeth )
{
    if( ctx )
    {
        ctx->coreBioMeth = coreBioMeth;
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

const BIO_METHOD* GsProvCtxGet0CoreBioMeth( GsProvCtx* ctx )
{
    return ctx ? ctx->coreBioMeth : NULL;
}