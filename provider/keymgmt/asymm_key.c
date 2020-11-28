#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <gostone/keymgmt/asymm_key.h>

struct gs_asymm_key_st
{
    OSSL_LIB_CTX* libCtx;
    char* properties;
    int algorithm;
    EC_GROUP* group;
    EC_POINT* publicKey;
    BIGNUM* privateKey;
};

GsAsymmKey* GsAsymmKeyNew( void )
{
    return ( GsAsymmKey* )OPENSSL_zalloc( sizeof( GsAsymmKey ) );
}

GsAsymmKey* GsAsymmKeyNewInit( OSSL_LIB_CTX* libCtx, int algorithm )
{
    GsAsymmKey* key = GsAsymmKeyNew();
    if( key )
    {
        GsAsymmKeySet0LibCtx( key, libCtx );
        GsAsymmKeySetAlgorithm( key, algorithm );
    }
    return key;
}

void GsAsymmKeyFree( GsAsymmKey* key )
{
    if( key )
    {
        EC_GROUP_free( key->group );
        BN_clear_free( key->privateKey );
        EC_POINT_clear_free( key->publicKey );
        OPENSSL_free( key );
    }
}

void GsAsymmKeySetAlgorithm( GsAsymmKey* key, int algorithm )
{
    OPENSSL_assert( key );
    key->algorithm = algorithm;
}

void GsAsymmKeySet0LibCtx( GsAsymmKey* key, OSSL_LIB_CTX* ctx )
{
    OPENSSL_assert( key );
    key->libCtx  = ctx;
}

int GsAsymmKeySet1Group( GsAsymmKey* key, const EC_GROUP* group )
{
    OPENSSL_assert( key );
    EC_GROUP_free( key->group );
    key->group = EC_GROUP_dup( group );
    return ( NULL != key->group );
}

int GsAsymmKeySet1PrivateKey( GsAsymmKey* key, const BIGNUM* privateKey )
{
    OPENSSL_assert( key );
    BN_free( key->privateKey );
    key->privateKey = BN_dup( privateKey );
    return ( NULL != key->privateKey );
}

int GsAsymmKeySet1PublicKey( GsAsymmKey* key, const EC_POINT* publicKey )
{
    OPENSSL_assert( key );
    EC_POINT_free( key->publicKey );
    key->publicKey = EC_POINT_dup( publicKey, GsAsymmKeyGet0Group( key ) );
    return ( NULL != key->publicKey );
}

int GsAsymmKeyDecodePublicKey( GsAsymmKey* key, const unsigned char* buf, size_t len )
{
    EC_POINT* publicKey;
    BN_CTX* ctx;
    int ret = 0;

    OPENSSL_assert( key );
    if( key->publicKey )
    {
        return 0;
    }
    if( !buf || 0 > len )
    {
        return 0;
    }
    ctx = BN_CTX_new_ex( key->libCtx );
    if( !ctx )
    {
        goto end;
    }
    key->publicKey = EC_POINT_new( key->group );
    if( !key->publicKey )
    {
        goto end;
    }
    ret = EC_POINT_oct2point( key->group, key->publicKey, buf, len, ctx );
end:
    if( !ret )
    {
        EC_POINT_free( key->publicKey );
        key->publicKey = NULL;
    }
    BN_CTX_free( ctx );
    return 1;
}

int GsAsymmKeyGetAlgorithm( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return key->algorithm;
}

int GsAsymmKeyGetParamset( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return EC_GROUP_get_curve_name( key->group );
}

OSSL_LIB_CTX* GsAsymmKeyGet0LibCtx( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return key->libCtx;
}


const EC_GROUP* GsAsymmKeyGet0Group( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return key->group;
}

const EC_POINT* GsAsymmKeyGet0PublicKey( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return key->publicKey;
}

const BIGNUM* GsAsymmKeyGet0PrivateKey( const GsAsymmKey* key )
{
    OPENSSL_assert( key );
    return key->privateKey;
}

int GsAsymmKeyGetKeySize( const GsAsymmKey* key )
{
    switch( GsAsymmKeyGetAlgorithm( key ) )
    {
    case NID_id_GostR3410_2012_256:
        return 32;
    case NID_id_GostR3410_2012_512:
        return 64;
    default:
        OPENSSL_assert( 0 );
        break;
    }
    return 0;
}

int GsAsymmKeyGetKeyBits( const GsAsymmKey* key )
{
    return GsAsymmKeyGetKeySize( key ) << 8;
}

int GsAsymmKeyGetDefaultDigest( const GsAsymmKey* key )
{
    switch( GsAsymmKeyGetAlgorithm( key ) )
    {
    case NID_id_GostR3410_2012_256:
        return NID_id_GostR3411_2012_256;
    case NID_id_GostR3410_2012_512:
        return NID_id_GostR3411_2012_512;
    default:
        OPENSSL_assert( 0 );
        break;
    }
    return NID_undef;
}


int GsAsymmKeyGeneratePublicKey( GsAsymmKey* key, BN_CTX* ctx )
{
    const BIGNUM* privateKey = GsAsymmKeyGet0PrivateKey( key );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    EC_POINT* publicKey;
    int ret = 0;

    if( !group || !privateKey )
    {
        goto end;
    }
    publicKey = EC_POINT_new( group );
    if( !publicKey )
    {
        goto end;
    }
    if( !EC_POINT_mul( group, publicKey, privateKey, NULL, NULL, ctx ) )
    {
        goto end;
    }
    ret = GsAsymmKeySet1PublicKey( key, publicKey );
end:
    EC_POINT_free( publicKey );
    return ret;
}

int GsAsymmKeyGenerate( GsAsymmKey* key )
{
    BN_CTX* ctx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( key ) );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    BIGNUM* d = BN_secure_new();
    BIGNUM* order;
    int ret = 0;

    if( !group )
    {
        return 0;
    }

    BN_CTX_start( ctx );
    order = BN_CTX_get( ctx ); 
    if( !order || !d )
    {
        return 0;
    }

    if( !EC_GROUP_get_order( group, order, ctx ) )
    {
        return 0;
    }
    do
    {
        if( !BN_priv_rand_range( d, order ) )
        {
            return 0;
        }
    }
    while( BN_is_zero( d ) );

    if( !GsAsymmKeySet1PrivateKey( key, d ) )
    {
        return 0;
    }
    ret = GsAsymmKeyGeneratePublicKey( key, ctx );
end:
    BN_clear_free( d );
    BN_CTX_end( ctx );
    BN_CTX_free( ctx );
    return ret;
}
