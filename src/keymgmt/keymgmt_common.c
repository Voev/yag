#include <openssl/param_build.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <yag/common.h>
#include <yag/provider_ctx.h>
#include <yag/implementations.h>
#include <yag/keymgmt/keymgmt_akey.h>
#include <yag/keymgmt/keymgmt_impl.h>
#include <yag/keymgmt/keymgmt_params.h>
#include <string.h>

void* GsKeyMgmtNew_( void* provData, int algorithm )
{
    GsProvCtx* provCtx = INTERPRET_AS_PROV_CTX( provData );
    OSSL_LIB_CTX* libCtx = GsProvCtxGet0LibCtx( provCtx );
    return GsAsymmKeyNewInit( libCtx, algorithm );
}

void* GsKeyMgmtNew( void* provData )
{
    return GsKeyMgmtNew_( provData, NID_id_GostR3410_2012_256 );
}

void* GsKeyMgmtNew512( void* provData )
{
    return GsKeyMgmtNew_( provData, NID_id_GostR3410_2012_512 );
}

void GsKeyMgmtFree( void* keyData )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    GsAsymmKeyFree( key );
}

void* GsKeyMgmtLoad( const void* reference, size_t referenceSize )
{
    GsAsymmKey* key = NULL;
    if( referenceSize == sizeof( key ) )
    {
        key = *( GsAsymmKey** )reference;
        *( GsAsymmKey** )reference = NULL;
        return key;
    }
    return NULL;
}

const OSSL_PARAM* GsKeyMgmtGettableParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gKeyMgmtGettableParams[] = 
    {
        OSSL_PARAM_int( OSSL_PKEY_PARAM_BITS, NULL ),
        OSSL_PARAM_int( OSSL_PKEY_PARAM_SECURITY_BITS, NULL ),
        OSSL_PARAM_int( OSSL_PKEY_PARAM_MAX_SIZE, NULL ),
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0 ),
        OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0 ),
        OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PUB_KEY, NULL, 0 ),
        OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0 ),
        OSSL_PARAM_END
    };
    return gKeyMgmtGettableParams;
}

int GsKeyMgmtGetParams( void* keyData, OSSL_PARAM params[] )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    const EC_GROUP* group = NULL;
    BN_CTX* bnCtx = NULL;
    OSSL_PARAM* p;
    int ret = 0;

    bnCtx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( key ) );
    if( !bnCtx )
    {
        return 0;
    }
    BN_CTX_start( bnCtx );

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_MAX_SIZE );
    if( p && !OSSL_PARAM_set_int( p, GsAsymmKeyGetKeySize( key ) ) )
    {
        goto end;
    }

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_BITS );
    if( p && !OSSL_PARAM_set_int( p, GsAsymmKeyGetKeyBits( key ) ) )
    {
        goto end;
    }

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_DEFAULT_DIGEST );
    if( p )
    {
        int nid = GsAsymmKeyGetDefaultDigest( key );
        if( !OSSL_PARAM_set_utf8_string( p, OBJ_nid2sn( nid ) ) )
        {
            goto end;
        }
    }
    
    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY );
    if( p ) 
    {
        p->return_size = EC_POINT_point2oct( GsAsymmKeyGet0Group( key ),
                                             GsAsymmKeyGet0PublicKey( key ),
                                             POINT_CONVERSION_UNCOMPRESSED,
                                             p->data, p->return_size, bnCtx );
        if (p->return_size == 0)
            goto end;
    }

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_GROUP_NAME );
    if( p )
    {
        int nid = GsAsymmKeyGetParamset( key );
        if( !OSSL_PARAM_set_utf8_string( p, OBJ_nid2sn( nid ) ) )
        {
            goto end;
        }
    }

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_PRIV_KEY );
    if( p )
    {
        const BIGNUM* privateKey = GsAsymmKeyGet0PrivateKey( key );
        if( !OSSL_PARAM_set_BN( p, privateKey ) )
        {
            goto end;
        }
    }

    p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_PUB_KEY );
    if( p )
    {
        const EC_POINT* publicKey = GsAsymmKeyGet0PublicKey( key );
        unsigned char* publicKeyBuf = NULL;
        size_t publicKeyLen = EC_POINT_point2buf( group, publicKey,
                                                  POINT_CONVERSION_COMPRESSED,
                                                  &publicKeyBuf, bnCtx );
        
        if( !OSSL_PARAM_set_octet_string( p, publicKeyBuf, publicKeyLen ) )
        {
            goto end;
        }
    } 
    ret = 1;
end:
    BN_CTX_end( bnCtx );
    BN_CTX_free( bnCtx );
    return ret;
}

const OSSL_PARAM* GsKeyMgmtSettableParams( ossl_unused void* provData )
{
    static const OSSL_PARAM gKeyMgmtSettableParams[] = 
    {
        OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0 ),
        OSSL_PARAM_END
    };
    return gKeyMgmtSettableParams;
}

int GsKeyMgmtSetParams( void* keyData, const OSSL_PARAM params[] )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    const OSSL_PARAM* p = OSSL_PARAM_locate_const( 
        params,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY
    );
    if( p )
    {
        if( p->data_type != OSSL_PARAM_OCTET_STRING ||
            !GsAsymmKeyDecodePublicKey( key, params->data, 
                                        params->data_size ) )
        {
            return 0;
        }
    }
    return 1;
}

int GsKeyMgmtExport( void* keyData, int selection, 
                     OSSL_CALLBACK* paramCb, void* cbArg )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    OSSL_PARAM_BLD* tmpl = NULL;
    BN_CTX* bnCtx = NULL;
    int ret = 1;

    if( !key )
    {
        return 0;
    }

    if( !( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) )
    {
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if( !tmpl )
    {
        goto end;
    }

    bnCtx = BN_CTX_new_ex( GsAsymmKeyGet0LibCtx( key ) );
    if( !bnCtx )
    {
        goto end;
    }
    BN_CTX_start( bnCtx );
    
    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) 
    {
        const char* name = OBJ_nid2sn( GsAsymmKeyGetParamset( key ) );
        ret &= OSSL_PARAM_BLD_push_utf8_string( tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                                name, strlen( name ) );
    }

    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) 
    {
        const BIGNUM* privateKey = GsAsymmKeyGet0PrivateKey( key );
        ret &= OSSL_PARAM_BLD_push_BN( tmpl, OSSL_PKEY_PARAM_PRIV_KEY, 
                                       privateKey );
    }

    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
    {
        const EC_POINT* publicKey = GsAsymmKeyGet0PublicKey( key );
        unsigned char* publicKeyBuf = NULL;
        size_t publicKeyLen = EC_POINT_point2buf( group, publicKey,
                                                  POINT_CONVERSION_COMPRESSED,
                                                  &publicKeyBuf, bnCtx );
        ret &= OSSL_PARAM_BLD_push_octet_string( tmpl, OSSL_PKEY_PARAM_PUB_KEY, 
                                                 publicKeyBuf, publicKeyLen );
    }

    if( ret )
    {
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param( tmpl );
        if( params )
        {
            ret = paramCb( params, cbArg );
        }
        OSSL_PARAM_free( params );
    }
end:
    OSSL_PARAM_BLD_free( tmpl );
    BN_CTX_end( bnCtx );
    BN_CTX_free( bnCtx );
    return ret;
}

int GsKeyMgmtImport( void* keyData, int selection, const OSSL_PARAM params[] )
{
    GsAsymmKey* key = INTERPRET_AS_ASYMM_KEY( keyData );
    const OSSL_PARAM* p = NULL;
    EC_GROUP* group = NULL;
    int ok = 1;

    if( !key )
    {
        return 0;
    }

    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS )
    {
        p = OSSL_PARAM_locate_const( params, OSSL_PKEY_PARAM_GROUP_NAME );
        if( !p )
        {
            return 0;
        }
        group = GsGetEcGroup( p );
        if( !GsAsymmKeySet1Group( key, group ) )
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) 
    {
        BIGNUM* privateKey = BN_secure_new();
        p = OSSL_PARAM_locate_const( params, OSSL_PKEY_PARAM_PRIV_KEY );
        OSSL_PARAM_get_BN( p, &privateKey );
        if( GsAsymmKeySet1PrivateKey( key, privateKey ) )
        {
            return 0;
        }
    }
    if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) 
    {
        unsigned char* publicKeyBuf = NULL;
        size_t publicKeyLen = 0;
        p = OSSL_PARAM_locate_const( params, OSSL_PKEY_PARAM_PUB_KEY );
        OSSL_PARAM_get_octet_string( p, ( void** )&publicKeyBuf, 0, &publicKeyLen );
        if( GsAsymmKeyDecodePublicKey( key, publicKeyBuf, publicKeyLen ) )
        {
            return 0;
        }
    }

    return ok;
}

static const OSSL_PARAM gKeyMgmtImportExportTypes[] = 
{
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0 ),
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PUB_KEY, NULL, 0 ),
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0 ),
    OSSL_PARAM_END
};

const OSSL_PARAM* GsKeyMgmtImportTypes( ossl_unused int selection )
{
    return gKeyMgmtImportExportTypes;
}

const OSSL_PARAM* GsKeyMgmtExportTypes( ossl_unused int selection )
{
    return gKeyMgmtImportExportTypes;
}