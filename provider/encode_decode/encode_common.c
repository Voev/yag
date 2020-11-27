#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

#include <gostone/common.h>
#include <gostone/provider_bio.h>
#include <gostone/provider_ctx.h>
#include <gostone/encode/encode.h>
#include <gostone/keymgmt/keymgmt.h>

struct gs_encoder_ctx_st
{
    GsProvCtx* provCtx;
    EVP_CIPHER* cipher;
};

static OSSL_FUNC_encoder_newctx_fn GsEncoderNewCtx;
static OSSL_FUNC_encoder_freectx_fn GsEncoderFreeCtx;
static OSSL_FUNC_encoder_set_ctx_params_fn GsEncoderSetCtxParams;
static OSSL_FUNC_encoder_settable_ctx_params_fn GsEncoderSettableCtxParams;
static OSSL_FUNC_encoder_import_object_fn GsEncoderImportObject;
static OSSL_FUNC_encoder_free_object_fn GsEncoderFreeObject;


static OSSL_FUNC_encoder_gettable_params_fn GsEncoderGettableParams;


static OSSL_FUNC_encoder_get_params_fn GsEncoderGetParamsKey256ToDer;
static OSSL_FUNC_encoder_get_params_fn GsEncoderGetParamsKey256ToPem;
static OSSL_FUNC_encoder_get_params_fn GsEncoderGetParamsKey512ToDer;
static OSSL_FUNC_encoder_get_params_fn GsEncoderGetParamsKey512ToPem;

static OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKey256ToDer;
static OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKey256ToPem;
static OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKey512ToDer;
static OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKey512ToPem;

const OSSL_DISPATCH gGostR341012_256ToPkcs8DerEncoderFuncs[] =
{
    { OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR( GsEncoderNewCtx ) },
    { OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR( GsEncoderFreeCtx ) },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, FUNC_PTR( GsEncoderGettableParams ) },
    { OSSL_FUNC_ENCODER_GET_PARAMS, FUNC_PTR( GsEncoderGetParamsKey256ToDer ) },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, FUNC_PTR( GsEncoderSettableCtxParams ) },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR( GsEncoderSetCtxParams ) },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR( GsEncoderImportObject ) },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR( GsEncoderFreeObject ) },
    { OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR( GsEncoderEncodeKey256ToDer ) },
    { 0, NULL }
};

const OSSL_DISPATCH gGostR341012_256ToPkcs8PemEncoderFuncs[] =
{
    { OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR( GsEncoderNewCtx ) },
    { OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR( GsEncoderFreeCtx ) },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, FUNC_PTR( GsEncoderGettableParams ) },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, FUNC_PTR( GsEncoderSettableCtxParams ) },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR( GsEncoderSetCtxParams ) },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR( GsEncoderImportObject ) },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR( GsEncoderFreeObject ) },
    { OSSL_FUNC_ENCODER_GET_PARAMS, FUNC_PTR( GsEncoderGetParamsKey256ToPem ) },
    { OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR( GsEncoderEncodeKey256ToPem ) },
    { 0, NULL }
};

const EVP_CIPHER* GsEncoderCtxGet0Cipher( GsEncoderCtx* ctx )
{
    return ctx ? ctx->cipher : NULL;
}

void* GsEncoderNewCtx( void* provCtx )
{
    GsEncoderCtx* ctx = OPENSSL_zalloc( sizeof( *ctx ) );
    if( ctx )
    {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

void GsEncoderFreeCtx( void* vctx )
{
    GsEncoderCtx* ctx = ( GsEncoderCtx* )vctx;
    if( ctx )
    {
        EVP_CIPHER_free( ctx->cipher );
        OPENSSL_free( ctx );
    }
}


int key2any_check_selection(int selection, int selection_mask)
{
    /*
     * The selections are kinda sorta "levels", i.e. each selection given
     * here is assumed to include those following.
     */
    int checks[] = {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    };
    size_t i;

    /* The decoder implementations made here support guessing */
    if (selection == 0)
        return 1;

    for (i = 0; i < OSSL_NELEM(checks); i++) {
        int check1 = (selection & checks[i]) != 0;
        int check2 = (selection_mask & checks[i]) != 0;

        /*
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         */
        if (check1)
            return check2;
    }

    /* This should be dead code, but just to be safe... */
    return 0;
}

const OSSL_PARAM* GsEncoderGettableParams( ossl_unused void* provCtx, int structure )
{
    static const OSSL_PARAM gGettableParams[] = 
    {
        { OSSL_ENCODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    static const OSSL_PARAM gGettableParamsStructure[] = 
    {
        { OSSL_ENCODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return structure ? gGettableParamsStructure : gGettableParams;
}

const OSSL_PARAM* GsEncoderSettableCtxParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gSettableCtxParams[] =
    {
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_CIPHER,     NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0 ),
        OSSL_PARAM_END,
    };
    return gSettableCtxParams;
}

int GsEncoderSetCtxParams( void* vctx, const OSSL_PARAM params[] )
{
    GsEncoderCtx* ctx = ( GsEncoderCtx* )vctx;
    OSSL_LIB_CTX* libCtx = GsProvCtxGet0LibCtx( ctx->provCtx );
    const OSSL_PARAM* cipherParam =
        OSSL_PARAM_locate_const( params, OSSL_ENCODER_PARAM_CIPHER );

    if( cipherParam )
    {
        const OSSL_PARAM* propsParam;

        propsParam = OSSL_PARAM_locate_const( params, OSSL_ENCODER_PARAM_PROPERTIES );

        const char* cipherName = NULL;
        const char* props = NULL;

        if( !OSSL_PARAM_get_utf8_string_ptr( cipherParam, &cipherName ) )
        {
            return 0;
        }
        if( props && !OSSL_PARAM_get_utf8_string_ptr( propsParam, &props ) )
        {
            return 0;
        }

        EVP_CIPHER_free( ctx->cipher );
        if( cipherName )
        {
            ctx->cipher = EVP_CIPHER_fetch( libCtx, cipherName, props );
        }
        return 0;
    }
    return 1;
}

int ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len;
    const EC_GROUP *ecg = NULL;
    EC_POINT *pub_point = NULL;
    int ok = 0;

    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    ctx = BN_CTX_new_ex(NULL);
    if (ctx == NULL)
        goto err;

    if (param_pub_key != NULL)
        if (!OSSL_PARAM_get_octet_string(param_pub_key,
                                         (void **)&pub_key, 0, &pub_key_len)
            || (pub_point = EC_POINT_new(ecg)) == NULL
            || !EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx))
        goto err;

    if (param_priv_key != NULL && include_private) {
        int fixed_words;
        const BIGNUM *order;

        order = EC_GROUP_get0_order(ecg);
        if (order == NULL || BN_is_zero(order))
            goto err;

        BN_set_flags(priv_key, BN_FLG_CONSTTIME);

        if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
            goto err;
    }

    if (priv_key != NULL
        && !EC_KEY_set_private_key(ec, priv_key))
        goto err;

    if (pub_point != NULL
        && !EC_KEY_set_public_key(ec, pub_point))
        goto err;

    ok = 1;

 err:
    BN_CTX_free(ctx);
    BN_clear_free(priv_key);
    OPENSSL_free(pub_key);
    EC_POINT_free(pub_point);
    return ok;
}

int ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    EC_GROUP* group = NULL;
    int ret = 0;

    const OSSL_PARAM* groupName = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if( !groupName ) 
    {
        goto end;
    }

    group = GsGetEcGroup( groupName );
    if( !group )
    {
        goto end;
    }
    ret = EC_KEY_set_group(ec, group);
end:
    EC_GROUP_free(group);
    return ret;
}

void* GsEncoderImportObject( void* vctx, int selection, const OSSL_PARAM params[] )
{
    EC_KEY *ec = vctx;
    const EC_GROUP *ecg = NULL;
    int ok = 1;

    if( !ec )
    {
        return 0;
    }

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters (+optional other params)
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters are always optional
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && ec_group_fromdata(ec, params);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ec_key_fromdata(ec, params, include_private);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && 1;//ec_key_otherparams_fromdata(ec, params);

    return NULL;
}

void GsEncoderFreeObject( void* key )
{
    // @todo
}

static int GsEncoderGetParams( OSSL_PARAM params[],
                               const char* inputType,
                               const char* outputType,
                               const char* outputStruct )
{
    OSSL_PARAM* p = OSSL_PARAM_locate( params, OSSL_ENCODER_PARAM_INPUT_TYPE );
    if( p && !OSSL_PARAM_set_utf8_ptr( p, inputType ) )
    {
        return 0;
    }
    p = OSSL_PARAM_locate( params, OSSL_ENCODER_PARAM_OUTPUT_TYPE );
    if( p && !OSSL_PARAM_set_utf8_ptr( p, outputType ) )
    {
        return 0;
    }
    p = OSSL_PARAM_locate( params, OSSL_ENCODER_PARAM_OUTPUT_TYPE );
    if( p && !OSSL_PARAM_set_utf8_ptr( p, outputType ) )
    {
        return 0;
    }
    if( outputStruct ) 
    {
        p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE);
        if( p && !OSSL_PARAM_set_utf8_ptr( p, outputStruct ) )
        {
            return 0;
        }
    }
    return 1;
}

int GsEncoderGetParamsKey256ToDer( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "GOST2012_256", "DER", "pkcs8" );
}

int GsEncoderGetParamsKey256ToPem( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "GOST2012_256", "PEM", "pkcs8" );
}

int GsEncodeKey( GsEncoderCtx* ctx, OSSL_CORE_BIO* cout,
                 const void* key, const int keyNid,
                 GsEncodeKeyToBioFn encoder,
                 OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    int ret = 0;

    if( !key ) 
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
    } 
    else
    {
        BIO* out = GsProvBioNewFromCoreBio( ctx->provCtx, cout );
        if( out ) //&& ossl_pw_set_ossl_passphrase_cb( &ctx->pwdata, cb, cbArg ) )
        {
            ret = encoder( out, key, keyNid, ctx );
        }
        BIO_free( out );
    }
    return ret;
}

static int GsEncodeParams( GsEncoderCtx* ctx, OSSL_CORE_BIO* cout,
                           const void* key, const int keyNid,
                           GsEncodeParamsToBioFn encoder)
{
    int ret = 0;
    if( !key )
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    } 
    else 
    {
        BIO* out = GsProvBioNewFromCoreBio( ctx->provCtx, cout );
        if( out )
        {
            ret = encoder( out, key, keyNid );
        }
        BIO_free( out );
    } 
    return ret;
}

int GsEncoderEncodeKey( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                             const OSSL_PARAM keyAbstract[], int selection,
                             OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg,
                             const int keyNid, 
                             GsEncodeKeyToBioFn privateKeyBioEncoder,
                             GsEncodeKeyToBioFn publicKeyBioEncoder,
                             GsEncodeParamsToBioFn paramsBioEncoder )
{
    if( keyAbstract )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        return GsEncodeKey( ctx, cout, key, keyNid,
                            privateKeyBioEncoder, cb, cbArg );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        return GsEncodeKey( ctx, cout, key, keyNid,
                            publicKeyBioEncoder, cb, cbArg );
    }
    if( selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
    {
         return GsEncodeParams( ctx, cout, key, keyNid,
                                paramsBioEncoder );
    }
    ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
    return 0;
}

int GsEncoderEncodeKey256ToDer( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                const OSSL_PARAM keyAbstract[], int selection,
                                OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncodeKey( ctx, cout, key, keyAbstract, selection, cb, cbArg,
                               NID_id_GostR3410_2012_256,
                               GsEncodePrivateKeyToDerBio,
                               GsEncodePublicKeyToDerBio,
                               GsEncodeParamsToDerBio );
}

int GsEncoderEncodeKey256ToPem( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                const OSSL_PARAM keyAbstract[], int selection,
                                OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncodeKey( ctx, cout, key, keyAbstract, selection, cb, cbArg,
                               NID_id_GostR3410_2012_256,
                               GsEncodePrivateKeyToPemBio,
                               GsEncodePublicKeyToPemBio,
                               GsEncodeParamsToPemBio );
}
