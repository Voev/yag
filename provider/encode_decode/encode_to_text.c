#include <ctype.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/params.h>
#include <openssl/objects.h>
#include <gostone/common.h>

static OSSL_FUNC_encoder_newctx_fn GsTextEncoderNewCtx;
static OSSL_FUNC_encoder_freectx_fn GsTextEncoderFreeCtx;
static OSSL_FUNC_encoder_gettable_params_fn GsTextEncoderGettableParams;
static OSSL_FUNC_encoder_import_object_fn GsTextEncoderImportObject;
static OSSL_FUNC_encoder_free_object_fn GsTextEncoderFreeObject;

static OSSL_FUNC_encoder_get_params_fn GsTextEncoderGetKey256Params;
static OSSL_FUNC_encoder_get_params_fn GsTextEncoderGetKey512Params;

static OSSL_FUNC_encoder_encode_fn GsTextEncoderEncodeKey;

const OSSL_DISPATCH gGostR341012_256TextEncoderFuncs[] = 
{
    { OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR( GsTextEncoderNewCtx ) },
    { OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR( GsTextEncoderFreeCtx ) },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, FUNC_PTR( GsTextEncoderGettableParams ) },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR( GsTextEncoderImportObject ) },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR( GsTextEncoderFreeObject ) },
    { OSSL_FUNC_ENCODER_GET_PARAMS, FUNC_PTR( GsTextEncoderGetKey256Params ) },
    { OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR( GsTextEncoderEncodeKey ) },
    { 0, NULL }
};

const OSSL_DISPATCH gGostR341012_512TextEncoderFuncs[] = 
{
    { OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR( GsTextEncoderNewCtx ) },
    { OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR( GsTextEncoderFreeCtx ) },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, FUNC_PTR( GsTextEncoderGettableParams ) },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR( GsTextEncoderImportObject ) },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR( GsTextEncoderFreeObject ) },
    { OSSL_FUNC_ENCODER_GET_PARAMS, FUNC_PTR( GsTextEncoderGetKey512Params ) },
    { OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR( GsTextEncoderEncodeKey ) },
    { 0, NULL }
};

void* GsTextEncoderNewCtx( void* provCtx )
{
    return provCtx;
}

void GsTextEncoderFreeCtx( void* vctx ossl_unused )
{}

const OSSL_PARAM* GsTextEncoderGettableParams( void* provCtx )
{
    static const OSSL_PARAM gGettables[] = 
    {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END
    };

    return gGettables;
}

int GsTextEncoderGetParams( OSSL_PARAM params[], const char *input_type )
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, input_type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEXT"))
        return 0;

    return 1;
}

int GsTextEncoderGetKey256Params( OSSL_PARAM params[] )
{
    return GsTextEncoderGetParams( params, "GOST2012_256" );
}

int GsTextEncoderGetKey512Params( OSSL_PARAM params[] )
{
    return GsTextEncoderGetParams( params, "GOST2012_512" );
}

void* GsTextEncoderImportObject( void* vctx, int selection, const OSSL_PARAM params[] )
{
    // @todo
    return NULL;
}

void GsTextEncoderFreeObject( void* key )
{
    // @todo
}

int GsTextEncoderPrint( BIO* out, const void* key, int selection )
{
    const EC_KEY* akey = ( const EC_KEY* )key;
    const char *type_label = NULL;
    int ret = 0;

    if (out == NULL || akey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_label = "Private-Key";
    else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_label = "Public-Key";
    else if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_label = "EC-Parameters";

    const EC_GROUP* group = EC_KEY_get0_group( akey );
    int paramNid = EC_GROUP_get_curve_name( group );
    if( !BIO_printf( out, "ParameterSet: %s\n", OBJ_nid2ln( paramNid ) ) )
    {
        return 0;
    }
}

int GsTextEncoderEncodeKey( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                            const OSSL_PARAM keyAbstract[], int selection,
                            OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    if( !keyAbstract )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    BIO *out = 0;// bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = GsTextEncoderPrint( out, key, selection );

    BIO_free(out);
    return ret;
}
