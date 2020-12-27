#include <ctype.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <gostone/provider_bio.h>
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/encode/encode_pubkey.h>

static int GsEncodeToText( BIO* out, const void* keyData, int selection )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );

    if( !out || !key ) 
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) 
    {
        const BIGNUM* privateKey = GsAsymmKeyGet0PrivateKey( key );
        BIO_printf( out, "Private key:\n" );
        if( privateKey )
        {
            BN_print( out, privateKey );
            BIO_printf( out, "\n" );
        }
        else
        {
            BIO_printf( out, "<undefined>\n" );
        }
    } 
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) 
    {
        unsigned char* rawValue = NULL;
        int rawSize = GsSerializePublicKey( key, &rawValue );
        BIO_printf( out, "Public key:\n" );
        if( rawSize && 0 < rawSize )
        {
            int half = rawSize / 2;
            BIO_printf( out, "X: " );
            BIO_hex_string( out, -1, 16, rawValue, half );
            BIO_printf( out, "\nY: " );
            BIO_hex_string( out, -1, 16, rawValue + half, half );
            BIO_printf( out, "\n" );
            OPENSSL_free( rawValue );
        }
        else
        {
            BIO_printf( out, "<undefined>\n" );
        }
    }
    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        int algorithm = GsAsymmKeyGetAlgorithm( key );
        int paramset = GsAsymmKeyGetParamset( key );
        BIO_printf( out, "Algorithm: %s\n", OBJ_nid2sn( algorithm ) );
        BIO_printf( out, "Parameters: %s\n", OBJ_nid2sn( paramset ) );
    }
    return 1;
}

void* GsEncoderToTextNewCtx( void* provCtx )
{
    return provCtx;
}

void GsEncoderToTextFreeCtx( ossl_unused void* vctx )
{}

const OSSL_PARAM* GsEncoderToTextGettableParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gTextGettablePrams[] = 
    {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END
    };
    return gTextGettablePrams;
}

static int GsEncoderToTextGetParams( OSSL_PARAM params[], const char *input_type)
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

int GsEncoderToTextGetAllKeyParams256( OSSL_PARAM params[] )
{
    return GsEncoderToTextGetParams( params, "gost2012_256" );
}

int GsEncoderToTextEncode( void *vctx, OSSL_CORE_BIO *cout,
                           const void *key,
                           const OSSL_PARAM key_abstract[],
                           int selection,
                           ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
                           ossl_unused void *cbarg)
{
    int ret = 0;
    BIO* out;

    if( key_abstract )
    {
        return 0;
    }
    out = GsProvBioNewFromCoreBio( vctx, cout );
    if( out )
    {
        ret = GsEncodeToText( out, key, selection );
        BIO_free( out );
    }
    return ret;
}
