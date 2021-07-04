
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h> /* PEM_BUFSIZE and public PEM functions */
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/proverr.h>

#include <gostone/decode/decode_common.h>
#include <gostone/decode/decode_impl.h>
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/keymgmt/keymgmt_impl.h>
#include <gostone/provider_ctx.h>
#include <gostone/provider_bio.h>

struct gs_decoder_ctx_st
{
    GsProvCtx* provCtx;
    unsigned int flag_fatal : 1;
};

void* GsDecoderNewCtx(void* provCtx)
{
    GsDecoderCtx* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (NULL != ctx)
    {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

void GsDecoderFreeCtx(void* vctx)
{
    GsDecoderCtx* ctx = (GsDecoderCtx*)vctx;
    if (ctx)
    {
        OPENSSL_free(ctx);
    }
}

int GsDecoderCheckSelection(int selection, int selectionMask)
{
    int checks[] = {OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS};
    size_t size = sizeof(checks) / sizeof(*checks);
    size_t i;

    if (selection == 0)
    {
        return 1;
    }

    for (i = 0; i < size; i++)
    {
        int check = (selection & checks[i]) != 0;
        int checkMask = (selectionMask & checks[i]) != 0;

        if (check)
        {
            return checkMask;
        }
    }
    return 0;
}

int GsDecoderDoesPrivateKeyInfoSelection(ossl_unused void* provCtx,
                                         int selection)
{
    return GsDecoderCheckSelection(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
}

int GsDecoderDoesPublicKeyInfoSelection(ossl_unused void* provCtx,
                                        int selection)
{
    return GsDecoderCheckSelection(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
}

int GsDecoderDoesTypeSpecificSelection(ossl_unused void* provCtx, int selection)
{
    return GsDecoderCheckSelection(selection,
                                   OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
}

/*
static GsAsymmKey* GsDecodeKeyAsKeyBag(GsDecoderCtx* ctx,
                                       const unsigned char** der,
                                       long derLength)
{
    const X509_ALGOR* alg = NULL;
    GsAsymmKey* key = NULL;

    PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, der, derLength);
    if (NULL != p8inf && PKCS8_pkey_get0(NULL, NULL, NULL, &alg, p8inf) &&
        OBJ_obj2nid(alg->algorithm) == ctx->desc->evp_type)
    {
        key = d2i_PKCS8_(p8inf, GsProvCtxGet0LibCtx(ctx->provCtx), NULL);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return key;
}*/

int GsDecoderDecodePrivateKeyInfoFromDer(
    void* vctx, OSSL_CORE_BIO* cin, int selection, OSSL_CALLBACK* dataCb,
    void* dataCbArg, ossl_unused OSSL_PASSPHRASE_CALLBACK* pwCb,
    ossl_unused void* pwCbArg)
{
    GsDecoderCtx* ctx = (GsDecoderCtx*)vctx;
    BIO* in = GsProvBioNewFromCoreBio(ctx->provCtx, cin);
    GsAsymmKey* key = NULL;
    int ret = 0;

    if (0 == selection)
    {
        selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
    }

    if (0 == (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    (void)in;

    if (key != NULL)
    {
        OSSL_PARAM params[4];
        int objectType = OSSL_OBJECT_PKEY;
        const char* dataType = OBJ_nid2sn(GsAsymmKeyGetAlgorithm(key));

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objectType);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char*)dataType, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ret = dataCb(params, dataCbArg);
    }

    ret = 1;

    GsAsymmKeyFree(key);
    return ret;
}

int GsDecoderDecodeTypeSpecificFromDer(
    void* vctx, OSSL_CORE_BIO* cin, int selection, OSSL_CALLBACK* dataCb,
    void* dataCbArg, ossl_unused OSSL_PASSPHRASE_CALLBACK* pwCb,
    ossl_unused void* pwCbArg)
{
    GsDecoderCtx* ctx = (GsDecoderCtx*)vctx;
    BIO* in = GsProvBioNewFromCoreBio(ctx->provCtx, cin);
    GsAsymmKey* key = NULL;
    int ret = 0;

    if (0 == selection)
    {
        selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
    }

    if (0 == (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    (void)in;

    if (key != NULL)
    {
        OSSL_PARAM params[4];
        int objectType = OSSL_OBJECT_PKEY;
        const char* dataType = OBJ_nid2sn(GsAsymmKeyGetAlgorithm(key));

        params[0] =

            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objectType);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char*)dataType, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ret = dataCb(params, dataCbArg);
    }

    ret = 1;

    GsAsymmKeyFree(key);
    return ret;
}

int GsDecoderExportObject(ossl_unused void* vctx, const void* reference,
                          size_t referenceSize, OSSL_CALLBACK* exportCb,
                          void* exportCbArg)
{
    void* keyData = NULL;
    if (referenceSize == sizeof(keyData))
    {
        keyData = *(void**)reference;
        return GsKeyMgmtExport(keyData, OSSL_KEYMGMT_SELECT_ALL, exportCb,
                               exportCbArg);
    }
    return 0;
}
