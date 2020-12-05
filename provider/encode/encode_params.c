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
int GsConvertAlgToHashParam( const int keyNid )
{
    int hashParamNid = NID_undef;
    switch( keyNid )
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
int GsGetHashParam( const int keyNid, const int keyParamNid )
{
    if( ( keyNid == NID_id_GostR3410_2012_256 &&
          keyParamNid == NID_id_tc26_gost_3410_2012_256_paramSetA ) ||
        ( keyNid == NID_id_GostR3410_2012_512 &&
          keyParamNid == NID_id_tc26_gost_3410_2012_512_paramSetC ) )
    {
        return NID_undef;
    }
    return GsConvertAlgToHashParam( keyNid );
}

static
GostKeyParams* GsEncoderCreateParams( const void* keyData )
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY( keyData );
    const EC_GROUP* group = GsAsymmKeyGet0Group( key );
    const int keyNid = GsAsymmKeyGetAlgorithm( key );
    GostKeyParams* params;
    int hashParamNid;
    int keyParamNid;

    if( !group )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER );
        return 0;
    }
    
    params = GostKeyParams_new();
    if( !params )
    {
        ERR_raise( ERR_LIB_PROV, ERR_R_MALLOC_FAILURE );
        return 0;
    }
    
    keyParamNid = EC_GROUP_get_curve_name( group );
    hashParamNid = GsGetHashParam( keyNid, keyParamNid );

    params->keyParams  = OBJ_nid2obj( keyParamNid );
    params->hashParams = hashParamNid == NID_undef ? NULL : OBJ_nid2obj( hashParamNid );
    params->cipherParams = NULL;
    return params;
}

int GsPrepareParams( const void* keyData, ASN1_STRING** params )
{
    GostKeyParams* keyParams = GsEncoderCreateParams( keyData );
    *params = ASN1_item_pack( keyParams, ASN1_ITEM_rptr( GostKeyParams ), NULL );
    GostKeyParams_free( keyParams );
    return 1;
}

static int GsEncodeKeyParamsToDerBio( BIO* out, const void* keyData,
                                      ossl_unused GsEncoderCtx* ctx,
                                      ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                      ossl_unused void* cbArg  )
{
    GostKeyParams* keyParams = GsEncoderCreateParams( keyData );
    int ret = ASN1_item_i2d_bio( ASN1_ITEM_rptr( GostKeyParams ), out, keyParams );
    GostKeyParams_free( keyParams );
    return ret;
}

static int GsEncodeKeyParamsToPemBio( BIO* out, const void* keyData,
                                      ossl_unused GsEncoderCtx* ctx,
                                      ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, 
                                      ossl_unused void* cbArg )
{
    GostKeyParams* keyParams = GsEncoderCreateParams( keyData );
    int ret = PEM_write_bio_GostKeyParams( out, keyParams );
    GostKeyParams_free( keyParams );
    return ret;
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

int GsEncoderEncodeKeyParamsToDer( void* ctx, OSSL_CORE_BIO* cout, const void* keyData,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, keyData, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                            cb, cbArg, GsEncodeKeyParamsToDerBio );
}

int GsEncoderEncodeKeyParamsToPem( void* ctx, OSSL_CORE_BIO* cout, const void* keyData,
                                   const OSSL_PARAM keyAbstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg )
{
    return GsEncoderEncode( ctx, cout, keyData, keyAbstract, 
                            selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                            cb, cbArg, GsEncodeKeyParamsToPemBio );
}
