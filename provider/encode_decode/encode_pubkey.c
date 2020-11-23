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

typedef int ( *EncodePublicKeyFn )( BIO* bio, const X509_PUBKEY* x );

int GsSerializePublicKey( const void* key, unsigned char** buffer )
{
    EC_KEY* akey = ( EC_KEY* )key;
    const EC_POINT* publicKey = EC_KEY_get0_public_key( akey );
    const EC_GROUP* group     = EC_KEY_get0_group( akey );
    const BIGNUM*   order     = EC_GROUP_get0_order( group );

    BIGNUM* X = BN_new();
    BIGNUM* Y = BN_new();

    if( !EC_POINT_get_affine_coordinates( group, publicKey, X, Y, NULL ) )
    {
        return 0;
    }

    int pointSize = 2 * BN_num_bytes( order );
    unsigned char* encPoint = OPENSSL_zalloc( pointSize );
    if( !encPoint )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return 0;
    }
    BN_bn2bin( X, encPoint + BN_num_bytes( order ) );
    BN_bn2bin( Y, encPoint );
    BUF_reverse( encPoint, NULL, pointSize );
    if( buffer )
    {
        *buffer = encPoint;
    }
    return pointSize;
}

int GsEncodeAsOctetString( const void* key, unsigned char** buffer )
{
    ASN1_OCTET_STRING* encOctet = NULL;
    unsigned char* encValue = NULL;
    unsigned char* rawValue = NULL;
    int encSize = 0;
    int rawSize = 0;

    if( !buffer )
    {
        return 0;
    }
    *buffer = NULL;

    rawSize = GsSerializePublicKey( key, &rawValue );
    if( 0 > rawSize || !rawValue )
    {
        goto end;
    }

    encOctet = ASN1_OCTET_STRING_new();
    if( !encOctet )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto end;
    }

    if( !ASN1_STRING_set( encOctet, rawValue, rawSize ) )
    {
        goto end;
    }

    encSize = i2d_ASN1_OCTET_STRING( encOctet, &encValue );
end:
    ASN1_OCTET_STRING_free( encOctet );
    OPENSSL_free( rawValue );
    *buffer = encValue;
    return encSize;
}

static X509_PUBKEY* GsEncodeKeyAsX509PubKey( const void* key, int keyNid, 
                                             ASN1_STRING* params )
{
    X509_PUBKEY* xpk = NULL;
    unsigned char* der = NULL;
    int derlen;

    xpk = X509_PUBKEY_new();
    if( !xpk || 
        0 >= ( derlen = GsEncodeAsOctetString( key, &der )) ||
        !X509_PUBKEY_set0_param( xpk, OBJ_nid2obj(keyNid),
                                 V_ASN1_SEQUENCE, params, der, derlen ) ) 
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        X509_PUBKEY_free( xpk );
        OPENSSL_free( der );
        xpk = NULL;
    }
    return xpk;
}

static int GsEncodeKeyToBio( BIO* out, const void* key, int keyNid,
                             GsEncoderCtx* ctx,
                             EncodePublicKeyFn encodePublicKey )
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY* xpk = NULL;
    ASN1_STRING* params = NULL;
    
    if( !GsPrepareParams( key, keyNid, &params ) )
    {
        return 0;
    }
 
    xpk = GsEncodeKeyAsX509PubKey( key, keyNid, params );
    if( xpk )
    {
        ret = encodePublicKey( out, xpk );
    }
    X509_PUBKEY_free( xpk );
    return ret;
}

int GsEncodePublicKeyToDerBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx )
{
    return GsEncodeKeyToBio( out, key, keyNid, ctx, 
                             i2d_X509_PUBKEY_bio );
}

int GsEncodePublicKeyToPemBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx )
{
    return GsEncodeKeyToBio( out, key, keyNid, ctx, 
                             PEM_write_bio_X509_PUBKEY );
}
