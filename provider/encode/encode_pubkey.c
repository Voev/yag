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
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/encode/encode_params.h>
#include <gostone/encode/encode_pubkey.h>

typedef int ( *EncodePublicKeyFn )( BIO* bio, const X509_PUBKEY* x );

int GsSerializePublicKey( const void* keyData, unsigned char** buffer )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    const EC_POINT* publicKey = GsAsymmKeyGet0PublicKey( key );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    const BIGNUM* order = EC_GROUP_get0_order( group );
    unsigned char* encPoint;
    int pointSize = 0;
    BN_CTX* ctx = NULL;
    BIGNUM* X;
    BIGNUM* Y;

    if( !buffer )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        goto end;
    }
    *buffer = NULL;

    ctx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( key ) );
    if( !ctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto end;
    }
    BN_CTX_start( ctx );
    X = BN_CTX_get( ctx );
    Y = BN_CTX_get( ctx );
    if( !Y || !EC_POINT_get_affine_coordinates( group, publicKey, X, Y, ctx ) )
    {
        goto end;
    }

    pointSize = 2 * BN_num_bytes( order );
    encPoint = OPENSSL_zalloc( pointSize );
    if( !encPoint )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto end;
    }
    BN_bn2bin( X, encPoint + BN_num_bytes( order ) );
    BN_bn2bin( Y, encPoint );
    BUF_reverse( encPoint, NULL, pointSize );
    *buffer = encPoint;
end:
    BN_CTX_end( ctx );
    BN_CTX_free( ctx );
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

static X509_PUBKEY* GsEncodeKeyAsX509PubKey( const void* keyData, 
                                             ASN1_STRING* params )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    X509_PUBKEY* xpk = NULL;
    unsigned char* der = NULL;
    int derlen;

    xpk = X509_PUBKEY_new();
    if( !xpk || 
        0 >= ( derlen = GsEncodeAsOctetString( key, &der )) ||
        !X509_PUBKEY_set0_param( xpk, OBJ_nid2obj( GsAsymmKeyGetAlgorithm( key ) ),
                                 V_ASN1_SEQUENCE, params, der, derlen ) ) 
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        X509_PUBKEY_free( xpk );
        OPENSSL_free( der );
        xpk = NULL;
    }
    return xpk;
}

static int GsEncodeKeyToBio( BIO* out, 
                             const void* key,
                             EncodePublicKeyFn encodePublicKey )
{
    ASN1_STRING* params = NULL;
    X509_PUBKEY* xpk = NULL;
    int ret = 0;
    
    if( !GsPrepareParams( key, &params ) )
    {
        return 0;
    }
 
    xpk = GsEncodeKeyAsX509PubKey( key, params );
    if( xpk )
    {
        ret = encodePublicKey( out, xpk );
    }
    X509_PUBKEY_free( xpk );
    return ret;
}

int GsEncoderDoesPublicKeySelection( ossl_unused void* ctx, int selection )
{
    return GsEncoderCheckSelection( selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY );
}

int GsEncodePublicKeyToDerBio( BIO* out, const void* key, 
                               ossl_unused GsEncoderCtx* ctx,
                               ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                               ossl_unused void* cbArg )
{
    return GsEncodeKeyToBio( out, key, i2d_X509_PUBKEY_bio );
}

int GsEncodePublicKeyToPemBio( BIO* out, const void* key,
                               ossl_unused GsEncoderCtx* ctx,
                               ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                               ossl_unused void* cbArg )
{
    return GsEncodeKeyToBio( out, key, PEM_write_bio_X509_PUBKEY );
}

int GsEncoderEncodePublicKeyToDer( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                            cb, cbArg, GsEncodePublicKeyToDerBio );
}

int GsEncoderEncodePublicKeyToPem( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                            cb, cbArg, GsEncodePublicKeyToPemBio );
}
