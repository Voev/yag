#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <gostone/common.h>
#include <gostone/provider_ctx.h>
#include <gostone/keymgmt/keymgmt.h>

struct gs_keymngm_gen_ctx
{
    OSSL_LIB_CTX* libCtx;
    char* group_name;
    int selection;
    EC_GROUP* genGroup;
};

typedef struct gs_keymngm_gen_ctx GsKeyMgmtGenCtx;

void* GsKeyMgmtGenInit( void* provCtx, int selection )
{
    OSSL_LIB_CTX* libCtx = GsProvCtxGet0LibCtx( ( GsProvCtx* )provCtx );
    GsKeyMgmtGenCtx* gctx = OPENSSL_zalloc( sizeof( *gctx ) );
    if( gctx )
    {
        gctx->libCtx = libCtx;
        gctx->selection = selection;
    }
    return gctx;
}

int GsKeyMgmtGenSetTemplate( void* genctx, void* templ )
{
    GsKeyMgmtGenCtx* gctx = ( GsKeyMgmtGenCtx* )genctx;
    EC_KEY* key = templ;
    const EC_GROUP* actualGroup;
    EC_GROUP* dupGroup;

    if( !gctx )
    {
        return 0;
    }
    actualGroup = EC_KEY_get0_group( key );
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
    EC_GROUP_free( gctx->genGroup );
    gctx->genGroup = dupGroup;
    return 1;
}

int GsKeyMgmtGenSetParams( void* genCtx, const OSSL_PARAM params[] )
{
    int ret = 1;
    GsKeyMgmtGenCtx* gctx = ( GsKeyMgmtGenCtx* )genCtx;

    const OSSL_PARAM* p = OSSL_PARAM_locate_const( params,
                                                   OSSL_PKEY_PARAM_GROUP_NAME );
    if( p )
    {
        EC_GROUP* group = GsGetEcGroup( p );
        gctx->genGroup = group;
    }
    return ret;
}

const OSSL_PARAM* GsKeyMgmtGenSettableParams(
    void* provCtx ossl_unused
)
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

void* GsKeyMgmtGen(
    void* genCtx,
    OSSL_CALLBACK* cb ossl_unused,
    void* cbArg ossl_unused )
{
    GsKeyMgmtGenCtx* gctx = ( GsKeyMgmtGenCtx* )genCtx;
    EC_GROUP* group = NULL;
    EC_KEY* key = NULL;
    int ret = 0;

    if( !gctx )
    {
        return NULL;
    }

    key = EC_KEY_new_ex( gctx->libCtx, NULL );
    if( !key )
    {
        return NULL;
    }

    group = gctx->genGroup;
    if( !group )
    {
        goto end;
    }
    if( !EC_KEY_set_group( key, group ) )
    {
        return 0;
    }

    if( gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR )
    {
        ret = EC_KEY_generate_key( key );
    }
    if( ret )
    {
        return key;
    }
end:
    EC_KEY_free( key );
    return NULL;
}

void GsKeyMgmtGenCleanup( void* genCtx )
{
    if( genCtx )
    {
        OPENSSL_free( genCtx );
    }
}
