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
#include <gostone/keymgmt/asymm_key.h>
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/encode/encode_params.h>
#include "asn1_params.h"

static
int convertAlgToHashParam( const int algNid )
{
    int hashParamNid = NID_undef;
    switch( algNid )
    {
    case NID_id_GostR3410_94:
    case NID_id_GostR3410_2001:
        hashParamNid = NID_id_GostR3411_94_CryptoProParamSet;
        break;
    case NID_id_GostR3410_2012_256:
        hashParamNid = NID_id_GostR3411_2012_256;
        break;
    case NID_id_GostR3410_2012_512:
        hashParamNid = NID_id_GostR3411_2012_512;
        break;
    default:
        break;
    }
    return hashParamNid;
}

static
GostKeyParams* GsEncoderGetParams_( const void* keyData )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    const int keyNid = GsAsymmKeyGetAlgorithm( key );
    
    if( !group )
    {
        return 0;
    }
    
    int curveNid = EC_GROUP_get_curve_name(group);
    GostKeyParams* gparams = GostKeyParams_new();
    if( !gparams )
    {
        return 0;
    }
    gparams->keyParams  = OBJ_nid2obj( curveNid );
    if( ( keyNid == NID_id_GostR3410_2012_256 &&
          curveNid == NID_id_tc26_gost_3410_2012_256_paramSetA ) ||
        ( keyNid == NID_id_GostR3410_2012_512 &&
          curveNid == NID_id_tc26_gost_3410_2012_512_paramSetC ) )
    {
        gparams->hashParams = NULL;
    }
    else
    {
        gparams->hashParams = OBJ_nid2obj( convertAlgToHashParam( keyNid ) );
    }
    return gparams;
}

int GsPrepareParams( const void* key, ASN1_STRING** params )
{
    GostKeyParams* gparams = GsEncoderGetParams_( key );
    *params = ASN1_item_pack( gparams, ASN1_ITEM_rptr( GostKeyParams ), NULL );
    GostKeyParams_free( gparams );
    return 1;
}

static int GsEncodeKeyParamsToDerBio( BIO* out, const void* key,
                                      ossl_unused GsEncoderCtx* ctx,
                                      ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                      ossl_unused void* cbArg  )
{
    return ASN1_item_i2d_bio( ASN1_ITEM_rptr( GostKeyParams ), out, GsEncoderGetParams_( key ) );
}

static int GsEncodeKeyParamsToPemBio( BIO* out, const void* key,
                                      ossl_unused GsEncoderCtx* ctx,
                                      ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                      ossl_unused void* cbArg )
{
    return PEM_write_bio_GostKeyParams( out, GsEncoderGetParams_( key ) );
}

int GsEncoderDoesKeyParamsSelection( ossl_unused void* ctx, int selection )
{
    return GsEncoderCheckSelection( selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS );
}

int GsEncoderGetKeyParams256ToDer( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "gost2012_256", "DER", "type-specific" );
}

int GsEncoderGetKeyParams256ToPem( OSSL_PARAM params[] )
{
    return GsEncoderGetParams( params, "gost2012_256", "PEM", "type-specific" );
}

int GsEncoderEncodeKeyParamsToDer( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                            cb, cbArg, GsEncodeKeyParamsToDerBio );
}

int GsEncoderEncodeKeyParamsToPem( void* ctx, OSSL_CORE_BIO* cout, const void* key,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, key, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                            cb, cbArg, GsEncodeKeyParamsToPemBio );
}
