#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <gostone/provider_ctx.h>
#include <gostone/keymgmt/keymgmt_impl.h>
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/keymgmt/keymgmt_params.h>

struct gs_keymngm_gen_ctx
{
    OSSL_LIB_CTX* libCtx;
    int algorithm;
    char* group_name;
    int selection;
    EC_GROUP* genGroup;
};
typedef struct gs_keymngm_gen_ctx GsKeyGenCtx;

void* GsKeyMgmtGenInit( void* provData, int selection )
{
    GsProvCtx* provCtx = INTERPRET_AS_PROV_CTX( provData );
    GsKeyGenCtx* gctx = OPENSSL_zalloc( sizeof( *gctx ) );
    if( gctx )
    {
        gctx->libCtx = GsProvCtxGet0LibCtx( provCtx );
        gctx->algorithm = NID_id_GostR3410_2012_256;
        gctx->selection = selection;
    }
    return gctx;
}

int GsKeyMgmtGenSetTemplate( void* genCtx, void* tmpl )
{
    GsKeyGenCtx* ctx = ( GsKeyGenCtx* )genCtx;
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( tmpl );
    const EC_GROUP* actualGroup;
    EC_GROUP* dupGroup;

    if( !ctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    actualGroup = GsAsymmKeyGet0Group( key );
    if( !actualGroup )
    {
        return 0;
    }
    dupGroup = EC_GROUP_dup( actualGroup );
    if( !dupGroup )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return 0;
    }
    EC_GROUP_free( ctx->genGroup );
    ctx->genGroup = dupGroup;
    ctx->algorithm = GsAsymmKeyGetAlgorithm( key );
    return 1;
}

int GsKeyMgmtGenSetParams( void* genCtx, const OSSL_PARAM params[] )
{
    GsKeyGenCtx* gctx = ( GsKeyGenCtx* )genCtx;
    const OSSL_PARAM* p = OSSL_PARAM_locate_const( params,
                                                   OSSL_PKEY_PARAM_GROUP_NAME );
    if( p )
    {
        EC_GROUP* group = GsGetEcGroup( p );
        gctx->genGroup = group;
    }
    return 1;
}

const OSSL_PARAM* GsKeyMgmtGenSettableParams( void* provCtx ossl_unused )
{
    static OSSL_PARAM gGenSettable[] =
    {
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0 ),
        OSSL_PARAM_END
    };
    return gGenSettable;
}

void* GsKeyMgmtGen( void* genCtx, OSSL_CALLBACK* cb ossl_unused,
                    void* cbArg ossl_unused )
{
    GsKeyGenCtx* ctx = ( GsKeyGenCtx* )genCtx;
    GsAsymmKey* key = NULL;
    
    if( !ctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return NULL;
    }
    key = ( GsAsymmKey* )GsAsymmKeyNewInit( ctx->libCtx, ctx->algorithm );
    if( !key )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return NULL;
    }
    if( !GsAsymmKeySet1Group( key, ctx->genGroup ) )
    {
        goto err;
    }
    if( ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR )
    {
        if( 0 >= GsAsymmKeyGenerate( key ) )
        {
            goto err;
        }
    }
    return key;
err:
    GsAsymmKeyFree( key );
    return NULL;
}

void GsKeyMgmtGenCleanup( void* genData )
{
    GsKeyGenCtx* genCtx = ( GsKeyGenCtx* )genData;
    if( genCtx )
    {
        EC_GROUP_free( genCtx->genGroup );
        OPENSSL_free( genCtx );
    }
}
