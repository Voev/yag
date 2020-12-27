#include <string.h> 
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/signature/signature_impl.h>
#include <gostone/provider_ctx.h>

#define GS_MAX_DIGEST_NAME_SIZE 128

typedef 
struct gs_sign_ctx_st
{
    OSSL_LIB_CTX* libCtx;
    char* property;
    GsAsymmKey* key;

    int operation;
    EVP_MD* md;
    EVP_MD_CTX* mdCtx;
    char mdName[ GS_MAX_DIGEST_NAME_SIZE ];
    size_t mdSize;
    BIGNUM* r;

} GsSignCtx;

#define INTERPRET_AS_SIGNCTX( x ) ( ( GsSignCtx* )( x ) )

void* GsSignatureNewCtx( void* provCtx, const char* property )
{
    GsSignCtx* ctx = OPENSSL_zalloc( sizeof( GsSignCtx ) );
    if( !ctx )
    {
        goto err;
    }
    ctx->libCtx = GsProvCtxGet0LibCtx( provCtx );
    if( property ) 
    {
        ctx->property = OPENSSL_strdup( property );
        if( !ctx->property )
        {
            goto err;
        }
    }
    return ctx;
err:
    ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
    OPENSSL_free( ctx );
    return NULL;
}

static void GsSignatureDigestFree( GsSignCtx* ctx )
{
    if( ctx )
    {
        OPENSSL_free( ctx->property );
        ctx->property = NULL;

        EVP_MD_CTX_free( ctx->mdCtx );
        ctx->mdCtx = NULL;
        
        EVP_MD_free( ctx->md );
        ctx->md = NULL;
        ctx->mdSize = 0;
    }
}

void GsSignatureFreeCtx( void* vctx )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( ctx )
    {
        GsSignatureDigestFree( ctx );
        GsAsymmKeyFree( ctx->key );
        BN_clear_free( ctx->r );
        OPENSSL_free( ctx );
    }
}

void* GsSignatureDupCtx( void* vctx )
{
    GsSignCtx* srcCtx = INTERPRET_AS_SIGNCTX( vctx );
    GsSignCtx* dstCtx = OPENSSL_zalloc( sizeof( *srcCtx ) );
    if( !dstCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return NULL;
    }

    *dstCtx       = *srcCtx;
    dstCtx->key   = NULL;
    dstCtx->md    = NULL;
    dstCtx->mdCtx = NULL;

    if( srcCtx->key )
    {
        if( 1 ) //EVP_MD_up_ref( srcCtx->md ) )
        {
            dstCtx->key = srcCtx->key;
        }
        else
        {
            goto err;
        }
    }

    if( srcCtx->md )
    {
        if( EVP_MD_up_ref( srcCtx->md ) )
        {
            dstCtx->md = srcCtx->md;
        }
        else
        {
            goto err;
        }
    }

    if( srcCtx->mdCtx ) 
    {
        dstCtx->mdCtx = EVP_MD_CTX_new();
        if( !dstCtx->mdCtx || 
            !EVP_MD_CTX_copy_ex( dstCtx->mdCtx, srcCtx->mdCtx ) )
        {
            goto err;
        }
    }
    return dstCtx;
err:
    GsSignatureFreeCtx( dstCtx );
    return NULL;
}

int GsSignatureSignVerifyInit( void* vctx, void* keyData )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    if( keyData )
    {
        GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
        GsAsymmKeyFree( ctx->key );
        ctx->key = GsAsymmKeyDuplicate( key );
    }
    return 1;
}

int GsSignatureSign( void* vctx, 
                     unsigned char* sig, size_t* siglen, size_t sigSize,
                     const unsigned char* tbs, size_t tbslen )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    const BIGNUM* privateKey;
    const EC_GROUP* group;
    BIGNUM* left,
          * rigth,
          * k, 
          * s, 
          * x, 
          * r, 
          * order, 
          * e, 
          * alpha;
    EC_POINT* C = NULL;
    BN_CTX* bctx = NULL;
    size_t half;
    int ret = 0;

    if( !ctx || !siglen )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    OPENSSL_assert( tbslen == 32 || tbslen == 64 );

    *siglen = 2 * tbslen;

    if( sigSize < *siglen )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }

    if( !sig )
    {
        return 1;
    }

    bctx = BN_CTX_new();
    if( !bctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return 0;
    }
    BN_CTX_start( bctx );

    group = GsAsymmKeyGet0Group( ctx->key );
    privateKey = GsAsymmKeyGet0PrivateKey( ctx->key );
    if( !group || !privateKey )
    {
        goto end;
    }

    C = EC_POINT_new( group );
    left  = BN_CTX_get( bctx );
    rigth = BN_CTX_get( bctx );
    k     = BN_CTX_get( bctx );
    s     = BN_CTX_get( bctx );
    x     = BN_CTX_get( bctx );
    r     = BN_CTX_get( bctx );
    order = BN_CTX_get( bctx );

    if( !C || !left || !rigth || !k || !s || !x || !r )
    {
        goto end;
    }
    if( !order || !EC_GROUP_get_order( group, order, bctx ) )
    {
        goto end;
    }

    /*
     * Step 1. alpha := digest as a bignum
     * Step 2. e := alpha (mod q), where q is order
     *         if e == 0 then e := 1
     */
    alpha = BN_lebin2bn( tbs, tbslen, NULL );
    e = BN_CTX_get( bctx );
    if( !alpha || !e || !BN_mod( e, alpha, order, bctx ) )
    {
        goto end;
    }
    if( BN_is_zero( e ) )
    {
        BN_one( e );
    }

    /*
     * Step 3. k \in_R (0, q), q = $order
     * ...
     * Step 4. C := k * P, where P \in $group
     *         C := (x_C, y_C)
     *         r := x_C (mod q)
     *         if r == 0 then goto Step 3.
     */
    do {
        do {
            if( !BN_rand_range( k, order ) ||
                !BN_add( k, k, order ) ||
                ( BN_num_bits( k ) <= BN_num_bits( order ) && !BN_add( k, k, order ) ) ||
                !EC_POINT_mul( group, C, k, NULL, NULL, bctx ) ||
                !EC_POINT_get_affine_coordinates( group, C, x, NULL, bctx ) ||
                !BN_nnmod( r, x, order, bctx ) )
            {
                goto end;
            }
        }
        while( BN_is_zero( r ) );

        /*
         * Step 5. s = ( r * d + k * e ) % q, where
         *         d = $privateKey, q = $order
         */
        if( !BN_mod_mul( left, privateKey, r, order, bctx ) ||
            !BN_mod_mul( rigth, k, e, order, bctx ) ||
            !BN_mod_add( s, left, rigth, order, bctx ) )
        {
            goto end;
        }
    }
    while( BN_is_zero( s ) );

    /*
     * Step 6. zeta := ( \underline{r} || \underline{s} ),
     *         zeta is the signature in LE (Little Endian)
     */
    half = *siglen / 2;
    ret = BN_bn2lebinpad( s, sig       , half ) &&
          BN_bn2lebinpad( r, sig + half, half );
end:
    EC_POINT_free( C );
    BN_free( alpha );
    BN_CTX_end( bctx );
    BN_CTX_free( bctx );
    return ret;
}

int GsSignatureVerify( void* vctx, 
                       const unsigned char* sig, size_t siglen,
                       const unsigned char* tbs, size_t tbslen )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    const EC_POINT* publicKey;
    const EC_GROUP* group;
    const BIGNUM* s, *r;
    BIGNUM* e,* z1,* z2,* nr,* X,* R,* v,* order,* alpha;
    EC_POINT* C = NULL;
    BN_CTX* bctx = NULL;
    size_t half;
    int ret = 0;

    if( !ctx || !tbs )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        goto end;
    }

    bctx = BN_CTX_new();
    if( !bctx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto end;
    }
    BN_CTX_start( bctx );

    group = GsAsymmKeyGet0Group( ctx->key );
    publicKey = GsAsymmKeyGet0PublicKey( ctx->key );
    if( !group || !publicKey )
    {
        goto end;
    }

    C     = EC_POINT_new( group );
    e     = BN_CTX_get( bctx );
    z1    = BN_CTX_get( bctx );
    z2    = BN_CTX_get( bctx );
    nr    = BN_CTX_get( bctx );
    X     = BN_CTX_get( bctx );
    R     = BN_CTX_get( bctx );
    v     = BN_CTX_get( bctx );
    order = BN_CTX_get( bctx );

    if( !C || !e || !z1 || !z2 || !nr || !X || !R || !v )
    {
        goto end;
    }
    if( !order || !EC_GROUP_get_order( group, order, bctx ) )
    {
        goto end;
    }

    /*
     * Step 1. r and s must be in (0, q),
     *         else signature is invalid
     */
    half = siglen / 2;
    s = BN_lebin2bn( sig,        half, NULL );
    r = BN_lebin2bn( sig + half, half, NULL );

    if( BN_is_zero( r ) || 1 == BN_cmp( r, order ) ||
        BN_is_zero( s ) || 1 == BN_cmp( s, order ) )
    {
        goto end;
    }

    /*
     * Step 2. alpha := digest as a bignum
     * Step 3. e := alpha (mod q), where q is order
     *         if e == 0 then e := 1
     */
    alpha = BN_lebin2bn( tbs, tbslen, NULL );
    if( !alpha || !BN_mod( e, alpha, order, bctx ) )
    {
        goto end;
    }
    if( BN_is_zero( e ) )
    {
        BN_one( e );
    }
    /*
     * Step 4. v   := e^{-1} (mod q), where q = $order
     * Step 5. z1  := s * v (mod q)
     *         $nr := $order - r = -r
     *         z2  := $nr * v (mod q)
     * Step 6. C   := z1 * P + z_2 * Q,
     *         where P := generator of $group, Q = $publicKey
     *         C   := (x_C, y_C)
     *         R   := x_C (mod q)
     */
    if( !BN_mod_inverse( v, e, order, bctx ) ||
        !BN_mod_mul( z1, s, v, order, bctx ) ||
        !BN_sub( nr, order, r ) ||
        !BN_mod_mul( z2, nr, v, order, bctx ) ||
        !EC_POINT_mul( group, C, z1, publicKey, z2, bctx ) ||
        !EC_POINT_get_affine_coordinates( group, C, X,
                                          NULL, bctx ) ||
        !BN_mod( R, X, order, bctx ) )
    {
        goto end;
    }

    /*
     * Step 7. R == r ? signature is correct : signature is invalid
     */
    if( 0 != BN_cmp( R, r ) )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_INTERNAL_ERROR );
        ERR_add_error_data( 1, "invalid signature" );
        goto end;
    }

    ret = 1;
end:
    BN_CTX_end( bctx );
    BN_CTX_free( bctx );
    return ret;
}

int GsSignatureDigestSignVerifyInit( void* vctx, const char* mdName,
                                     void* keyData )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    GsSignatureDigestFree( ctx );

    if( !GsSignatureSignVerifyInit( vctx, keyData ) )
    {
        return 0;
    }

    ctx->md     = EVP_MD_fetch( ctx->libCtx, mdName, ctx->property );
    ctx->mdSize = EVP_MD_size( ctx->md );
    ctx->mdCtx  = EVP_MD_CTX_new();
    if( !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        goto err;
    }

    if( !EVP_DigestInit_ex( ctx->mdCtx, ctx->md, NULL ) )
    {
        goto err;
    }
    return 1;
err:
    GsSignatureDigestFree( ctx );
    return 0;
}

int GsSignatureDigestSignVerifyUpdate( void* vctx, 
                                       const unsigned char* data, size_t datalen )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx || !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    return EVP_DigestUpdate( ctx->mdCtx, data, datalen );
}

int GsSignatureDigestSignFinal( void* vctx, unsigned char* sig, size_t* siglen,
                                size_t sigsize )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    unsigned char digest[ EVP_MAX_MD_SIZE ] = { 0 };
    unsigned int dlen = 0;
    
    if( !ctx || !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    if( sig && !EVP_DigestFinal_ex( ctx->mdCtx, digest, &dlen ) )
    {
        return 0;
    }
    return GsSignatureSign( vctx, sig, siglen, sigsize,
                            digest, ( size_t )dlen );
}

int GsSignatureDigestVerifyFinal( void* vctx, 
                                  const unsigned char* sig, size_t siglen )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    unsigned char digest[ EVP_MAX_MD_SIZE ] = { 0 };
    unsigned int dlen = 0;

    if( !ctx || !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    if( !EVP_DigestFinal_ex( ctx->mdCtx, digest, &dlen ) )
    {
        return 0;
    }
    return GsSignatureVerify( ctx, sig, siglen, digest, ( size_t )dlen );
}

int GsSignatureGetCtxParams( void* vctx, OSSL_PARAM* params )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    OSSL_PARAM* p;

    if( !ctx || !params )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }

    /*
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len))
        return 0;
    */

    p = OSSL_PARAM_locate( params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE );
    if( p  && !OSSL_PARAM_set_size_t( p, ctx->mdSize ) )
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if( p && !OSSL_PARAM_set_utf8_string( p, ctx->md == NULL
                                          ? EVP_MD_name( ctx->md ) 
                                          : ctx->mdName ) )
    {
        return 0;
    }
    return 1;
}

const OSSL_PARAM* GsSignatureGettableCtxParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gSignatureGettableCtxParams[] = 
    {
        // OSSL_PARAM_octet_string( OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0 ),
        OSSL_PARAM_size_t( OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL ),
        OSSL_PARAM_utf8_string( OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0 ),
        OSSL_PARAM_END
    };
    return gSignatureGettableCtxParams;
}

int GsSignatureGetCtxMdParams( void* vctx, OSSL_PARAM* params )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx || !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    return EVP_MD_CTX_get_params( ctx->mdCtx, params );
}

const OSSL_PARAM* GsSignatureGettableCtxMdParams( void* vctx )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx || !ctx->md )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    return EVP_MD_gettable_ctx_params( ctx->md );
}

int GsSignatureSetCtxParams( void* vctx, const OSSL_PARAM params[] )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    const OSSL_PARAM* p;
    char* mdName;

    if( !ctx || !params )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }

    if( ctx->md ) 
    {
        /*
         * You cannot set the digest name/size when doing a DigestSign or
         * DigestVerify.
         */
        return 1;
    }

    p = OSSL_PARAM_locate_const( params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE );
    if( p && !OSSL_PARAM_get_size_t( p, &ctx->mdSize ) )
    {
        return 0;
    }

    p = OSSL_PARAM_locate_const( params, OSSL_SIGNATURE_PARAM_DIGEST );
    mdName = ctx->mdName;
    if( p )
    {
        if( !OSSL_PARAM_get_utf8_string( p, &mdName, sizeof( ctx->mdName ) ) )
        {
            return 0;
        }
        ctx->md     = EVP_MD_fetch( ctx->libCtx, mdName, ctx->property );
        ctx->mdSize = EVP_MD_size( ctx->md );
    }
    return 1;
}

const OSSL_PARAM* GsSignatureSettableCtxParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gSignatureSettableCtxParams[] = 
    {
        OSSL_PARAM_size_t( OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL ),
        OSSL_PARAM_utf8_string( OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0 ),
        OSSL_PARAM_uint( OSSL_SIGNATURE_PARAM_KAT, NULL ),
        OSSL_PARAM_END
    };
    return gSignatureSettableCtxParams;
}

int GsSignatureSetCtxMdParams( void* vctx, const OSSL_PARAM params[] )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx || !ctx->mdCtx )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    return EVP_MD_CTX_set_params( ctx->mdCtx, params );
}

const OSSL_PARAM* GsSignatureSettableCtxMdParams( void* vctx )
{
    GsSignCtx* ctx = INTERPRET_AS_SIGNCTX( vctx );
    if( !ctx || !ctx->md )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT );
        return 0;
    }
    return EVP_MD_settable_ctx_params( ctx->md );
}
