#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <yag/common.h>
#include <yag/implementations.h>
#include <yag/digests/streebog_core.h>

static void* StreebogNewCtx( void* provCtx );
static void StreebogFreeCtx( void* ctx );
static void* StreebogDupCtx( void* ctx );
static int Streebog256Init( void* ctx );
static int Streebog512Init( void* ctx );
static int StreebogUpdate( void* ctx, const unsigned char* in, size_t inl );
static int StreebogFinal( void* ctx, unsigned char* out, size_t* outl,
                          size_t outsz );
static const OSSL_PARAM* StreebogGettableParams(void);
static int StreebogGetParams( OSSL_PARAM params[], const size_t digestSize );
static int Streebog256GetParams( OSSL_PARAM params[] );
static int Streebog512GetParams( OSSL_PARAM params[] );

const OSSL_DISPATCH gGostR341112_256Funcs[] =
{
    { OSSL_FUNC_DIGEST_INIT,            FUNC_PTR( Streebog256Init ) },
    { OSSL_FUNC_DIGEST_GET_PARAMS,      FUNC_PTR( Streebog256GetParams ) },
    { OSSL_FUNC_DIGEST_NEWCTX,          FUNC_PTR( StreebogNewCtx ) },
    { OSSL_FUNC_DIGEST_FREECTX,         FUNC_PTR( StreebogFreeCtx ) },
    { OSSL_FUNC_DIGEST_DUPCTX,          FUNC_PTR( StreebogDupCtx ) },
    { OSSL_FUNC_DIGEST_UPDATE,          FUNC_PTR( StreebogUpdate ) },
    { OSSL_FUNC_DIGEST_FINAL,           FUNC_PTR( StreebogFinal ) },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, FUNC_PTR( StreebogGettableParams ) },
};

const OSSL_DISPATCH gGostR341112_512Funcs[] =
{
    { OSSL_FUNC_DIGEST_INIT,            FUNC_PTR( Streebog512Init ) },
    { OSSL_FUNC_DIGEST_GET_PARAMS,      FUNC_PTR( Streebog512GetParams ) },
    { OSSL_FUNC_DIGEST_NEWCTX,          FUNC_PTR( StreebogNewCtx ) },
    { OSSL_FUNC_DIGEST_FREECTX,         FUNC_PTR( StreebogFreeCtx ) },
    { OSSL_FUNC_DIGEST_DUPCTX,          FUNC_PTR( StreebogDupCtx ) },
    { OSSL_FUNC_DIGEST_UPDATE,          FUNC_PTR( StreebogUpdate ) },
    { OSSL_FUNC_DIGEST_FINAL,           FUNC_PTR( StreebogFinal ) },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, FUNC_PTR( StreebogGettableParams ) },
};

void* StreebogNewCtx( void* provCtx ossl_unused )
{
    return OPENSSL_zalloc( GsStreebogCtxGetSize() );
}

void StreebogFreeCtx( void* ctx )
{
    OPENSSL_clear_free( ctx, GsStreebogCtxGetSize() );
}

void* StreebogDupCtx( void* ctx )
{
    return OPENSSL_memdup( ctx, GsStreebogCtxGetSize() );
}

int Streebog256Init( void* ctx )
{
    GsStreebogCtx* impl = ( GsStreebogCtx* )ctx;
    GsStreebogCtxSetDgstSize( impl, Streebog256LengthInBytes );
    GsStreebogCtxInit( impl );
    return 1;
}

int Streebog512Init( void* ctx )
{
    GsStreebogCtx* impl = ( GsStreebogCtx* )ctx;
    GsStreebogCtxSetDgstSize( impl, Streebog512LengthInBytes );
    GsStreebogCtxInit( impl );
    return 1;
}

int StreebogUpdate( void* ctx, const unsigned char* in, size_t inl )
{
    GsStreebogCtx* impl = ( GsStreebogCtx* )ctx;
    OPENSSL_assert( inl > 0 );
    if( !in )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    GsStreebogCtxUpdate( impl, in, inl );
    return 1;
}

int StreebogFinal( void* ctx, unsigned char* out, size_t* outl, size_t outsz )
{
    GsStreebogCtx* impl = ( GsStreebogCtx* )ctx;
    if( !out )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    OPENSSL_assert( outl );
    OPENSSL_assert( GsStreebogCtxGetDgstSize( impl ) == outsz );
    GsStreebogCtxFinal( impl, out );
    *outl = GsStreebogCtxGetDgstSize( impl );
    return 1;
}

const OSSL_PARAM* StreebogGettableParams( void )
{
    static const OSSL_PARAM table[] =
    {
        OSSL_PARAM_size_t( OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL ),
        OSSL_PARAM_size_t( OSSL_DIGEST_PARAM_SIZE,       NULL ),
        OSSL_PARAM_int( OSSL_DIGEST_PARAM_ALGID_ABSENT,  NULL ),
        OSSL_PARAM_END
    };
    return table;
}

int StreebogGetParams( OSSL_PARAM params[], const size_t digestSize )
{
    OSSL_PARAM* p = OSSL_PARAM_locate( params, OSSL_DIGEST_PARAM_BLOCK_SIZE );
    if( p && !OSSL_PARAM_set_size_t( p, BlockLengthInBytes ) )
    {
        return 0;
    }
    p = OSSL_PARAM_locate( params, OSSL_DIGEST_PARAM_SIZE );
    if( p && !OSSL_PARAM_set_size_t( p, digestSize ) )
    {
        return 0;
    }
    p = OSSL_PARAM_locate( params, OSSL_DIGEST_PARAM_ALGID_ABSENT );
    if( p && !OSSL_PARAM_set_int( p, 1 ) )
    {
        return 0;
    }
    return 1;
}

int Streebog256GetParams( OSSL_PARAM params[] )
{
    return StreebogGetParams( params, Streebog256LengthInBytes );
}

int Streebog512GetParams( OSSL_PARAM params[] )
{
    return StreebogGetParams( params, Streebog512LengthInBytes );
}
