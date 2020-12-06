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
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/keymgmt/keymgmt_impl.h>
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/keymgmt/keymgmt_params.h>

struct gs_encoder_ctx_st
{
    GsProvCtx* provCtx;
    EVP_CIPHER* cipher;
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

int GsEncoderCheckSelection( int selection, int selectionMask )
{
    int checks[] = 
    {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    };
    size_t size = sizeof( checks ) / sizeof( *checks );
    size_t i;

    if( selection == 0 )
    {
        return 1;
    }

    for( i = 0; i < size; i++ ) 
    {
        int check1 = (selection & checks[i]) != 0;
        int check2 = (selectionMask & checks[i]) != 0;

        if (check1)
        {
            return check2;
        }
    }
    return 0;
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

const OSSL_PARAM* GsEncoderSettableCtxParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gSettableCtxParams[] =
    {
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_CIPHER, NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0 ),
        OSSL_PARAM_END,
    };
    return gSettableCtxParams;
}

int GsEncoderGetParams( OSSL_PARAM params[], 
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

const OSSL_PARAM* GsEncoderGettableParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gGettableParams[] = 
    {
        { OSSL_ENCODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };
    return gGettableParams;
}

int GsEncoderEncode( GsEncoderCtx* ctx, OSSL_CORE_BIO* cout, const void* keyData,
                     const OSSL_PARAM keyAbstract[], 
                     int selection, int selectionMask,
                     OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg,
                     GsEncodeToBioFn encoderToBio )
{
    OPENSSL_assert( ctx );
    int ret = 0;

    if( keyAbstract || !( selection & selectionMask ) )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    if( !keyData )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
    } 
    else
    {
        BIO* out = GsProvBioNewFromCoreBio( ctx->provCtx, cout );
        if( out ) 
        {
            ret = encoderToBio( out, keyData, ctx, cb, cbArg );
        }
        BIO_free( out );
    }
    return ret;
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

void GsEncoderFreeObject( void* keyData )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    GsAsymmKeyFree( key );
}