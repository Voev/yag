#include <gostone/asn1/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <gostone/keymgmt/keymgmt_akey.h>

// clang-format off

typedef struct
{
    ASN1_OBJECT* keyParams;
    ASN1_OBJECT* hashParams;
    ASN1_OBJECT* cipherParams;
} GS_KEYPARAMS;

ASN1_NDEF_SEQUENCE(GS_KEYPARAMS) =
{
    ASN1_SIMPLE(GS_KEYPARAMS, keyParams, ASN1_OBJECT),
    ASN1_OPT(GS_KEYPARAMS, hashParams, ASN1_OBJECT),
    ASN1_OPT(GS_KEYPARAMS, cipherParams, ASN1_OBJECT),
}
ASN1_NDEF_SEQUENCE_END(GS_KEYPARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GS_KEYPARAMS)

IMPLEMENT_PEM_rw(GS_KEYPARAMS, GS_KEYPARAMS, "GOST KEY PARAMETERS",
                 GS_KEYPARAMS)


int i2d_GOST_KEYPARAMS_bio(BIO* out, GS_KEYPARAMS* keyParams)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(GS_KEYPARAMS), out, keyParams);
}

GS_KEYPARAMS* d2i_GOST_KEYPARAMS_bio(BIO* in)
{
    return (GS_KEYPARAMS*)ASN1_item_d2i_bio(ASN1_ITEM_rptr(GS_KEYPARAMS), in,
                                            NULL);
}

// clang-format on

static int GsConvertAlgToHashParam(const int keyNid)
{
    int hashParamNid = NID_undef;
    switch (keyNid)
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

static int GsGetHashParam(const int keyNid, const int keyParamNid)
{
    if ((keyNid == NID_id_GostR3410_2012_256 &&
         keyParamNid == NID_id_tc26_gost_3410_2012_256_paramSetA) ||
        (keyNid == NID_id_GostR3410_2012_512 &&
         keyParamNid == NID_id_tc26_gost_3410_2012_512_paramSetC))
    {
        return NID_undef;
    }
    return GsConvertAlgToHashParam(keyNid);
}

GS_KEYPARAMS* GsEncoderCreateParams(const void* keyData)
{
    const GsAsymmKey* key = INTERPRET_AS_CASYMM_KEY(keyData);
    const EC_GROUP* group = GsAsymmKeyGet0Group(key);
    const int keyNid = GsAsymmKeyGetAlgorithm(key);
    GS_KEYPARAMS* params;
    int hashParamNid;
    int keyParamNid;

    if (!group)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    params = GS_KEYPARAMS_new();
    if (!params)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    keyParamNid = EC_GROUP_get_curve_name(group);
    hashParamNid = GsGetHashParam(keyNid, keyParamNid);

    params->keyParams = OBJ_nid2obj(keyParamNid);
    params->hashParams =
        hashParamNid == NID_undef ? NULL : OBJ_nid2obj(hashParamNid);
    params->cipherParams = NULL;
    return params;
}

int GsPackKeyParams(const void* keyData, ASN1_STRING** params)
{
    GS_KEYPARAMS* keyParams = GsEncoderCreateParams(keyData);
    *params = ASN1_item_pack(keyParams, ASN1_ITEM_rptr(GS_KEYPARAMS), NULL);
    GS_KEYPARAMS_free(keyParams);
    return 1;
}

int GsEncodeKeyParamsToDerBioImpl(BIO* out, const void* keyData)
{
    GS_KEYPARAMS* keyParams = GsEncoderCreateParams(keyData);
    int ret = i2d_GOST_KEYPARAMS_bio(out, keyParams);
    GS_KEYPARAMS_free(keyParams);
    return ret;
}

int GsEncodeKeyParamsToPemBioImpl(BIO* out, const void* keyData)
{
    GS_KEYPARAMS* keyParams = GsEncoderCreateParams(keyData);
    int ret = PEM_write_bio_GS_KEYPARAMS(out, keyParams);
    GS_KEYPARAMS_free(keyParams);
    return ret;
}
/*

GsAsymmKey* GsParams2Key(GS_KEYPARAMS* keyParams)
{
    GsAsymmKey* key = GsAsymmKeyNew();
    return key;
    // GsAsymmKeySetAlgorithm(key, keyParams->)
}*/
