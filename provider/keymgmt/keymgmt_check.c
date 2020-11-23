#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <gostone/common.h>
#include <gostone/provider_ctx.h>
#include <gostone/keymgmt/keymgmt.h>

int GsKeyMgmtMatch( const void* keyDataA, const void* keyDataB, int selection )
{
    const EC_KEY* keyA = ( const EC_KEY* )keyDataA;
    const EC_KEY* keyB = ( const EC_KEY* )keyDataB;
    int ret = 1;

    if( !keyA || !keyB )
    {
        return 0;
    }

    BN_CTX* ctx = BN_CTX_new_ex( NULL );
    if( !ctx )
    {
        return 0;
    }

    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        const EC_GROUP* groupA = EC_KEY_get0_group( keyA );
        const EC_GROUP* groupB = EC_KEY_get0_group( keyB );
        ret &= ( groupA && groupB && 0 == EC_GROUP_cmp( groupA, groupB, ctx ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        const BIGNUM* keyValueA = EC_KEY_get0_private_key( keyA );
        const BIGNUM* keyValueB = EC_KEY_get0_private_key( keyB );
        ret &= ( 0 == BN_cmp( keyValueA, keyValueB ) );
    }
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        const EC_GROUP* groupA    = EC_KEY_get0_group( keyA );
        const EC_POINT* pubValueA = EC_KEY_get0_public_key( keyA );
        const EC_POINT* pubValueB = EC_KEY_get0_public_key( keyB );
        ret &= ( 0 == EC_POINT_cmp( groupA, pubValueA, pubValueB, ctx ) );
    }
    BN_CTX_free( ctx );
    return ret;
}

int GsKeyMgmtHas( const void* keyData, int selection )
{
    const EC_KEY* key = ( const EC_KEY* )keyData;
    int ret = 0;

    if( key )
    {
        if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
        {
            ret &= ( NULL != EC_KEY_get0_public_key( key ) );
        }
        if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
        {
            ret &= ( NULL != EC_KEY_get0_private_key( key ) );
        }
        if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
        {
            ret &= ( NULL != EC_KEY_get0_group( key ) );
        }
    }
    return ret;
}

static int GsKeyMgmtCheckPrivateKey( const EC_KEY* key )
{
    const EC_GROUP* group;
    const BIGNUM* value;

    if( !key )
    {
        return 0;
    }

    value = EC_KEY_get0_private_key( key );
    group = EC_KEY_get0_group( key );

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

static int GsKeyMgmtPairwiseCheck( const EC_KEY* key, BN_CTX* ctx )
{
    int ret = 0;
    EC_POINT* calcValue = NULL;
    const BIGNUM* privValue;
    const EC_POINT* pubValue;
    const EC_GROUP* group;
    if( !key )
    {
        return 0;
    }

    privValue = EC_KEY_get0_private_key( key );
    pubValue = EC_KEY_get0_public_key( key );
    group = EC_KEY_get0_group( key );

    if( !privValue || !pubValue || !group )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }

    calcValue = EC_POINT_new( group );
    if( !calcValue )
        goto err;

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

static int GsKeyMgmtCheckPublicKeyRange( BN_CTX* ctx, const EC_KEY* key )
{
    int ret = 0;
    BIGNUM *x, *y;
    const EC_GROUP* group = EC_KEY_get0_group( key );
    const EC_POINT* pubValue = EC_KEY_get0_public_key( key );
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_POINT_get_affine_coordinates( group, pubValue, x, y, ctx ) )
        goto err;

    const BIGNUM* field = EC_GROUP_get0_field( group );
    if (BN_is_negative(x)
            || BN_cmp(x, field) >= 0
            || BN_is_negative(y)
            || BN_cmp(y, field) >= 0) {
            goto err;
        }
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

static int GsKeyMgmtCheckPublicKey( const EC_KEY* key, BN_CTX* ctx )
{
    int ret = 0;
    EC_POINT *point = NULL;
    const BIGNUM *order = NULL;

    const EC_GROUP* group = EC_KEY_get0_group( key );
    const EC_POINT* pubValue = EC_KEY_get0_public_key( key );


    /* 5.6.2.3.3 (Step 1): Q != infinity */
    if (EC_POINT_is_at_infinity( group, pubValue ) )
    {
        ERR_raise( ERR_LIB_PROV, EC_R_POINT_AT_INFINITY );
        return 0;
    }

    point = EC_POINT_new( group );
    if (point == NULL)
        return 0;

    /* 5.6.2.3.3 (Step 2) Test if the public key is in range */
    if (!GsKeyMgmtCheckPublicKeyRange( ctx, key ) )
    {
        //ECerr(0, EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    /* 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve */
    if (EC_POINT_is_on_curve( group, pubValue, ctx) <= 0)
    {
        //ECerr(0, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }

    order = EC_GROUP_get0_order( group ) ;
    if (BN_is_zero( order ) )
    {
        //ECerr(0, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    /* 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. */
    if (!EC_POINT_mul( group, point, NULL, pubValue, order, ctx)) {
        //ECerr(0, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity( group, point)) {
        //ECerr(0, EC_R_WRONG_ORDER);
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free(point);
    return ret;
}

int GsKeyMgmtValidate( const void* keyData, int selection )
{
    const EC_KEY* key = ( const EC_KEY* )keyData;
    int ret = 1;

    BN_CTX* ctx = BN_CTX_new_ex( NULL );
    if( !ctx )
    {
        return 0;
    }
    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        ret &= EC_GROUP_check( EC_KEY_get0_group( key ), ctx );
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

