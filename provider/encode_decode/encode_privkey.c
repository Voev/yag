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
#include <gostone/encode/encode.h>

static 
int GsSerializePrivateKey( const void* key, unsigned char** buffer )
{
    const EC_KEY* akey = ( const EC_KEY* )key;
    const BIGNUM* privateKey = EC_KEY_get0_private_key( akey );
    int bufSize = BN_num_bytes( privateKey );
    unsigned char* buf = ( unsigned char* )OPENSSL_zalloc( bufSize );
    if( !buf )
    {
        return 0;
    }
    bufSize = BN_bn2bin( privateKey, buf );
    if( buffer )
    {
        *buffer = buf;
    }
    return bufSize;
}


static
PKCS8_PRIV_KEY_INFO* GsEncodeKeyAsKeyBag( const void* key, const int keyNid, ASN1_STRING* params )
{
    PKCS8_PRIV_KEY_INFO* p8info = PKCS8_PRIV_KEY_INFO_new();
    unsigned char* der = NULL;
    int derlen = GsSerializePrivateKey( key, &der );
    PKCS8_pkey_set0( p8info, OBJ_nid2obj( keyNid ), 0, V_ASN1_SEQUENCE, params, der, derlen );
    return p8info;
}

static
X509_SIG* GsEncodeKeyAsShroudedKeyBag(const void *key, int key_nid,
                                      ASN1_STRING* params, GsEncoderCtx* ctx )
{
    PKCS8_PRIV_KEY_INFO* p8info = GsEncodeKeyAsKeyBag( key, key_nid, params );
    X509_SIG *p8 = NULL;
    char kstr[PEM_BUFSIZE];
    size_t klen = 0;

    if( !GsEncoderCtxGet0Cipher( ctx ) )
    {
        return NULL;
    }

    //if (!ossl_pw_get_passphrase(kstr, sizeof(kstr), &klen, NULL, 1,
    //                            &ctx->pwdata)) {
    //    ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
    //    return NULL;
    //}
    p8 = PKCS8_encrypt(-1, GsEncoderCtxGet0Cipher( ctx ), kstr, klen, NULL, 0, 0, p8info);
    OPENSSL_cleanse(kstr, klen);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    return p8;
}

typedef int ( *EncodeShroudedKeyBagFn )( BIO* bio, const X509_SIG* x );
typedef int ( *EncodeKeyBagFn )( BIO* bio, const PKCS8_PRIV_KEY_INFO* x );

static int GsEncodeKeyToBio( BIO* out, const void* key, int keyNid,
                             GsEncoderCtx* ctx,
                             EncodeShroudedKeyBagFn encodeShrKeyBag,
                             EncodeKeyBagFn encodeKeyBag )
{
    int ret = 0;
    ASN1_STRING* params = NULL;
    
    if( !GsPrepareParams( key, keyNid, &params ) )
    {
        return 0;
    }
     
    if( GsEncoderCtxGet0Cipher( ctx ) ) 
    {
        X509_SIG* p8 = GsEncodeKeyAsShroudedKeyBag( key, keyNid, params, ctx );
        if( p8 )
        {
            ret = encodeShrKeyBag( out, p8 );
        }
        X509_SIG_free( p8 );
    } 
    else 
    {
        PKCS8_PRIV_KEY_INFO* p8info = GsEncodeKeyAsKeyBag( key, keyNid, params );
        if( p8info )
        {
            ret = encodeKeyBag( out, p8info );
        }
        PKCS8_PRIV_KEY_INFO_free( p8info );
    }
    return ret;
}

int GsEncodePrivateKeyToDerBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx )
{
    return GsEncodeKeyToBio( out, key, keyNid, ctx, 
                             i2d_PKCS8_bio, 
                             i2d_PKCS8_PRIV_KEY_INFO_bio );
}

int GsEncodePrivateKeyToPemBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx )
{
    return GsEncodeKeyToBio( out, key, keyNid, ctx, 
                             PEM_write_bio_PKCS8, 
                             PEM_write_bio_PKCS8_PRIV_KEY_INFO );
}
