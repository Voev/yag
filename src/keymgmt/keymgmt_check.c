#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <yag/common.h>
#include <yag/provider_ctx.h>
#include <yag/keymgmt/keymgmt_akey.h>
#include <yag/keymgmt/keymgmt_impl.h>

int GsKeyMgmtMatch( const void* keyDataA, const void* keyDataB, int selection )
{
    const GsAsymmKey* keyA = INTERPRET_AS_CASYMM_KEY( keyDataA );
    const GsAsymmKey* keyB = INTERPRET_AS_CASYMM_KEY( keyDataB );
    BN_CTX* ctx;
    int ret = 1;

    if( !keyA || !keyB )
    {
        return 0;
    }

    ctx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( keyA ) );
    if( !ctx )
    {
        return 0;
    }

    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        const EC_GROUP* groupA = GsAsymmKeyGet0Group( keyA );
        const EC_GROUP* groupB = GsAsymmKeyGet0Group( keyB );
        ret &= ( groupA && groupB && 0 == EC_GROUP_cmp( groupA, groupB, ctx ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        const BIGNUM* keyValueA = GsAsymmKeyGet0PrivateKey( keyA );
        const BIGNUM* keyValueB = GsAsymmKeyGet0PrivateKey( keyB );
        ret &= ( 0 == BN_cmp( keyValueA, keyValueB ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        const EC_GROUP* groupA    = GsAsymmKeyGet0Group( keyA );
        const EC_POINT* pubValueA = GsAsymmKeyGet0PublicKey( keyA );
        const EC_POINT* pubValueB = GsAsymmKeyGet0PublicKey( keyB );
        ret &= ( 0 == EC_POINT_cmp( groupA, pubValueA, pubValueB, ctx ) );
    }
    BN_CTX_free( ctx );
    return ret;
}

int GsKeyMgmtHas( const void* keyData, int selection )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    int ret = 1;

    if( !key )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        ret &= ( NULL != GsAsymmKeyGet0PublicKey( key ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        ret &= ( NULL != GsAsymmKeyGet0PrivateKey( key ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        ret &= ( NULL != GsAsymmKeyGet0Group( key ) );
    }
    return ret;
}

static int GsKeyMgmtCheckPrivateKey( const GsAsymmKey* key )
{
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    const BIGNUM* value   = GsAsymmKeyGet0PrivateKey( key );

    if( !value || !group )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    if( 0 >  BN_cmp( value, BN_value_one() ) ||
        0 <= BN_cmp( value, EC_GROUP_get0_order( group ) ) )
    {
        ERR_raise( ERR_LIB_PROV, EC_R_INVALID_PRIVATE_KEY );
        return 0;
    }
    return 1;
}

static int GsKeyMgmtPairwiseCheck( const GsAsymmKey* key, BN_CTX* ctx )
{
    const BIGNUM* privValue = GsAsymmKeyGet0PrivateKey( key );
    const EC_POINT* pubValue = GsAsymmKeyGet0PublicKey( key );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    EC_POINT* calcValue = NULL;
    int ret = 0;

    if( !privValue || !pubValue || !group )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }

    calcValue = EC_POINT_new( group );
    if( !calcValue )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto err;
    }

    if( !EC_POINT_mul( group, calcValue, privValue, NULL, NULL, ctx ) )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_EC_LIB );
        goto err;
    }
    if( 0 != EC_POINT_cmp( group, calcValue, pubValue, ctx ) )
    {
        ERR_raise( ERR_LIB_PROV, EC_R_INVALID_PRIVATE_KEY );
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free( calcValue );
    return ret;
}

static int GsKeyMgmtCheckPublicKeyRange( const GsAsymmKey* key, BN_CTX* ctx )
{
    const EC_POINT* pubValue = GsAsymmKeyGet0PublicKey( key );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    BIGNUM* x, * y;
    const BIGNUM* field;
    int ret = 0;
    BN_CTX_start( ctx );
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if( !x || !y )
    {
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates( group, pubValue, x, y, ctx ) )
    {
        goto err;
    }

    field = EC_GROUP_get0_field( group );
    if( BN_is_negative( x ) || 
        BN_cmp( x, field ) >= 0 || 
        BN_is_negative( y ) || 
        BN_cmp( y, field ) >= 0 ) 
    {
        goto err;
    }
    ret = 1;
err:
    BN_CTX_end( ctx );
    return ret;
}

static int GsKeyMgmtCheckPublicKey( const GsAsymmKey* key, BN_CTX* ctx )
{
    const EC_POINT* pubValue = GsAsymmKeyGet0PublicKey( key );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    const BIGNUM* order = NULL;
    EC_POINT* point = NULL;
    int ret = 0;

    if( EC_POINT_is_at_infinity( group, pubValue ) )
    {
        ERR_raise( ERR_LIB_PROV, EC_R_POINT_AT_INFINITY );
        return 0;
    }

    point = EC_POINT_new( group );
    if( !point )
    {
        return 0;
    }

    if( !GsKeyMgmtCheckPublicKeyRange( key, ctx ) )
    {
        ERR_raise( ERR_LIB_PROP, EC_R_COORDINATES_OUT_OF_RANGE );
        goto err;
    }

    if( 0 >= EC_POINT_is_on_curve( group, pubValue, ctx ) )
    {
        ERR_raise( ERR_LIB_PROP, EC_R_POINT_IS_NOT_ON_CURVE );
        goto err;
    }

    order = EC_GROUP_get0_order( group ) ;
    if( BN_is_zero( order ) )
    {
        ERR_raise( ERR_LIB_PROP, EC_R_INVALID_GROUP_ORDER );
        goto err;
    }

    if( !EC_POINT_mul( group, point, NULL, pubValue, order, ctx ) ) 
    {
        ERR_raise( ERR_LIB_PROP, ERR_R_EC_LIB );
        goto err;
    }
    if( !EC_POINT_is_at_infinity( group, point ) ) 
    {
        ERR_raise( ERR_LIB_PROP, EC_R_WRONG_ORDER );
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free( point );
    return ret;
}

int GsKeyMgmtValidate( const void* keyData, int selection, int checktype )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    int ret = 1;
    (void)checktype;

    BN_CTX* ctx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( key ) );
    if( !ctx )
    {
        return 0;
    }
    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        ret &= EC_GROUP_check( GsAsymmKeyGet0Group( key ), ctx );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        ret &= GsKeyMgmtCheckPublicKey( key, ctx );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        ret &= GsKeyMgmtCheckPrivateKey( key );
    }
    if( ( selection & OSSL_KEYMGMT_SELECT_KEYPAIR ) ==
            OSSL_KEYMGMT_SELECT_KEYPAIR )
    {
        ret &= GsKeyMgmtPairwiseCheck( key, ctx );
    }
    BN_CTX_free( ctx );
    return ret;
}

