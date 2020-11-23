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
GostKeyParams* GsEncoderGetParams( const void* key, const int keyNid )
{
    const EC_KEY* akey = ( const EC_KEY* )key;
    const EC_GROUP* group = EC_KEY_get0_group( key );
    
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

int GsPrepareParams( const void* key, int keyNid, ASN1_STRING** params )
{
    int curve_nid;
    GostKeyParams* gparams = GsEncoderGetParams( key, keyNid );
    *params = ASN1_item_pack( gparams, ASN1_ITEM_rptr( GostKeyParams ), NULL );
    return 1;
}

int GsEncodeParamsToDerBio( BIO* out, const void* key, const int keyNid )
{
    return ASN1_item_i2d_bio( ASN1_ITEM_rptr( GostKeyParams ), out,
                              GsEncoderGetParams( key, keyNid ) );
}

int GsEncodeParamsToPemBio( BIO* out, const void* key, const int keyNid )
{
    return PEM_write_bio_GostKeyParams( out, GsEncoderGetParams( key, keyNid ) );
}
