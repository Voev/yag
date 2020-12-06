#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/pkcs12.h>

#include <gostone/common.h>
#include <gostone/provider_ctx.h>
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/encode/encode_params.h>
#include <gostone/keymgmt/asymm_key.h>

static 
int GsSerializePrivateKey( const GsAsymmKey* key, unsigned char** buffer )
{
    const BIGNUM* privateKey = GsAsymmKeyGet0PrivateKey( key );
    unsigned char* buf;
    int bufSize;
    
    if( !buffer )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    *buffer = NULL;

    if( !privateKey )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }

    bufSize = BN_num_bytes( privateKey );
    buf = ( unsigned char* )OPENSSL_zalloc( bufSize );
    if( !buf )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return 0;
    }
    bufSize = BN_bn2bin( privateKey, buf );
    *buffer = buf;
    return bufSize;
}

static
PKCS8_PRIV_KEY_INFO* GsEncodeKeyAsKeyBag( const void* keyData, ASN1_STRING* params )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    PKCS8_PRIV_KEY_INFO* p8info = NULL;
    unsigned char* der = NULL;
    int derlen, keyNid;
    int ret = 0;

    if( !key )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        goto end;
    }
    keyNid = GsAsymmKeyGetAlgorithm( key );

    p8info = PKCS8_PRIV_KEY_INFO_new();
    if( !p8info )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto end;
    }

    derlen = GsSerializePrivateKey( key, &der );
    if( !PKCS8_pkey_set0( p8info, OBJ_nid2obj( keyNid ), 0, 
                          V_ASN1_SEQUENCE, params, der, derlen ) )
    {
        goto end;
    }

    ret = 1;
end:
    if( !ret )
    {
        PKCS8_PRIV_KEY_INFO_free( p8info );
        p8info = NULL;
    }
    return p8info;
}

static
X509_SIG* GsEncodeKeyAsShroudedKeyBag( const void* keyData,
                                       ASN1_STRING* params, 
                                       GsEncoderCtx* ctx )
{
    const EVP_CIPHER* cipher = GsEncoderCtxGet0Cipher( ctx );
    PKCS8_PRIV_KEY_INFO* p8info = NULL;
    char kstr[ PEM_BUFSIZE ] = { 0 };
    X509_SIG* p8 = NULL;
    size_t klen = 0;

    if( !cipher )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        goto end;
    }

    p8info = GsEncodeKeyAsKeyBag( keyData, params );
    if( !p8info )
    {
        goto end;
    }
    p8 = PKCS8_encrypt( -1, cipher, kstr, klen, NULL, 0, 0, p8info );
end:
    OPENSSL_cleanse( kstr, klen );
    PKCS8_PRIV_KEY_INFO_free( p8info );
    return p8;
}

typedef int ( *EncodeShroudedKeyBagFn )( BIO* bio, const X509_SIG* x );
typedef int ( *EncodeKeyBagFn )( BIO* bio, const PKCS8_PRIV_KEY_INFO* x );

static int GsEncodeKeyToBio( BIO* out, const void* key,
                             GsEncoderCtx* ctx,
                             EncodeShroudedKeyBagFn encodeShrKeyBag,
                             EncodeKeyBagFn encodeKeyBag )
{
    int ret = 0;
    ASN1_STRING* params = NULL;
    
    if( !GsPrepareParams( key, &params ) )
    {
        return 0;
    }
     
    if( GsEncoderCtxGet0Cipher( ctx ) ) 
    {
        X509_SIG* p8 = GsEncodeKeyAsShroudedKeyBag( key, params, ctx );
        if( p8 )
        {
            ret = encodeShrKeyBag( out, p8 );
        }
        X509_SIG_free( p8 );
    } 
    else 
    {
        PKCS8_PRIV_KEY_INFO* p8info = GsEncodeKeyAsKeyBag( key, params );
        if( p8info )
        {
            ret = encodeKeyBag( out, p8info );
        }
        PKCS8_PRIV_KEY_INFO_free( p8info );
    }
    return ret;
}

int GsEncoderDoesPrivateKeySelection( ossl_unused void* ctx, int selection )
{
    return GsEncoderCheckSelection( selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY );
}

int GsEncoderGetPrivateKeyParams256ToDer( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "gost2012_256", "DER", "pkcs8" );
}

int GsEncoderGetPrivateKeyParams256ToPem( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "gost2012_256", "PEM", "pkcs8" );
}

int GsEncodePrivateKeyToDerBio( BIO* out, const void* key, 
                                GsEncoderCtx* ctx,
                                ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                ossl_unused void* cbArg )
{
    return GsEncodeKeyToBio( out, key, ctx,
                             i2d_PKCS8_bio,
                             i2d_PKCS8_PRIV_KEY_INFO_bio );
}

int GsEncodePrivateKeyToPemBio( BIO* out, const void* key, 
                                GsEncoderCtx* ctx,
                                ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                ossl_unused void* cbArg )
{
    return GsEncodeKeyToBio( out, key, ctx,
                             PEM_write_bio_PKCS8,
                             PEM_write_bio_PKCS8_PRIV_KEY_INFO );
}

int GsEncoderEncodePrivateKeyToDer( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                    const OSSL_PARAM keyAbstract[], int selection,
                                    OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                            cb, cbArg, GsEncodePrivateKeyToDerBio );
}

int GsEncoderEncodePrivateKeyToPem( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                    const OSSL_PARAM keyAbstract[], int selection,
                                    OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                            cb, cbArg, GsEncodePrivateKeyToPemBio );
}

