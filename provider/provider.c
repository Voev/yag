#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <gostone/common.h>
#include <gostone/implementations.h>
#include <gostone/provider_bio.h>
#include <gostone/provider_ctx.h>

OSSL_provider_init_fn OSSL_provider_init;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn* CoreGettableParams = NULL;
static OSSL_FUNC_core_get_params_fn* CoreGetParams = NULL;

/* Parameters provided to the core */
static const OSSL_PARAM gGettableParams[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM* GsGettableParams(const OSSL_PROVIDER* prov ossl_unused)
{
    return gGettableParams;
}

static int GsGetParams(const OSSL_PROVIDER* prov ossl_unused,
                       OSSL_PARAM params[])
{
    OSSL_PARAM* p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Gostone Provider"))
    {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
    {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
    {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p && !OSSL_PARAM_set_int(p, 1))
    {
        return 0;
    }
    return 1;
}

static const OSSL_ALGORITHM gGsDigests[] = {
    {SN_id_GostR3411_2012_256, "provider=gostone", gGostR341112_256Funcs,
     LN_id_GostR3411_2012_256},
    {SN_id_GostR3411_2012_512, "provider=gostone", gGostR341112_512Funcs,
     LN_id_GostR3411_2012_512},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM gGsKeyMgmts[] = {
    {SN_id_GostR3410_2012_256, "provider=gostone", gGostR341012_256Funcs,
     LN_id_GostR3410_2012_256},
    {SN_id_GostR3410_2012_512, "provider=gostone", gGostR341012_512Funcs,
     LN_id_GostR3410_2012_512},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM gGsEncoders[] = {
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, PrivateKeyInfo, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, PrivateKeyInfo, Pem),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, SubjectPublicKeyInfo, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, SubjectPublicKeyInfo, Pem),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, TypeSpecific, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_256, TypeSpecific, Pem),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, PrivateKeyInfo, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, PrivateKeyInfo, Pem),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, SubjectPublicKeyInfo, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, SubjectPublicKeyInfo, Pem),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, TypeSpecific, Der),
    ENCODER_FOR_STRUCTURE(GostR3410_2012_512, TypeSpecific, Pem),
    TEXT_ENCODER(GostR3410_2012_256),
    TEXT_ENCODER(GostR3410_2012_512),
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM gGsDecoders[] = {{NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM gGsSignatures[] = {
    {SN_id_GostR3410_2012_256, "provider=gostone",
     gGostR341012_SignatureFunctions, LN_id_GostR3410_2012_256},
    {SN_id_GostR3410_2012_512, "provider=gostone",
     gGostR341012_SignatureFunctions, LN_id_GostR3410_2012_512},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM gGsCiphers[] = {
    {SN_kuznyechik_ecb, "provider=gostone", gKuznyechikECBFuncs,
     "GOST R 34.12-2015 Kuznyechik in ECB mode"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM* GsQuery(OSSL_PROVIDER* prov ossl_unused,
                                     int operation, int* noCache)
{
    const OSSL_ALGORITHM* alg = NULL;
    switch (operation)
    {
    case OSSL_OP_DIGEST:
        alg = gGsDigests;
        break;
    case OSSL_OP_KEYMGMT:
        alg = gGsKeyMgmts;
        break;
    case OSSL_OP_ENCODER:
        alg = gGsEncoders;
        break;
    case OSSL_OP_SIGNATURE:
        alg = gGsSignatures;
        break;
    case OSSL_OP_DECODER:
        alg = gGsDecoders;
        break;
    case OSSL_OP_CIPHER:
        alg = gGsCiphers;
        break;
    case OSSL_OP_MAC:
    case OSSL_OP_KDF:
    case OSSL_OP_RAND:
    case OSSL_OP_KEYEXCH:
        break;
    case OSSL_OP_ASYM_CIPHER:
    case OSSL_OP_KEM:
    default:
        alg = NULL;
        break;
    }
    if (noCache)
    {
        *noCache = 0;
    }
    return alg;
}

static void GsTeardown(void* provData)
{
    GsProvCtx* provCtx = INTERPRET_AS_PROV_CTX(provData);
    GsProvCtxFree(provCtx);
}

static const OSSL_DISPATCH gDispatchTable[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, FUNC_PTR(GsGettableParams)},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, FUNC_PTR(GsGetParams)},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, FUNC_PTR(GsQuery)},
    {OSSL_FUNC_PROVIDER_TEARDOWN, FUNC_PTR(GsTeardown)},
    {0, NULL}};

int OSSL_provider_init(const OSSL_CORE_HANDLE* handle, const OSSL_DISPATCH* in,
                       const OSSL_DISPATCH** out, void** provCtx)
{
    OSSL_FUNC_core_get_libctx_fn* CoreGetLibCtx = NULL;
    BIO_METHOD* coreBioMeth;

    if (!GsProvBioFromDispatch(in))
    {
        return 0;
    }

    for (; in->function_id != 0; ++in)
    {
        switch (in->function_id)
        {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            CoreGettableParams = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            CoreGetParams = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            CoreGetLibCtx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            break;
        }
    }

    if (!CoreGetLibCtx)
    {
        return 0;
    }

    *provCtx = GsProvCtxNew();
    if (!(*provCtx))
    {
        return 0;
    }
    coreBioMeth = GsProvBioInitBioMethod();
    if (!coreBioMeth)
    {
        GsProvCtxFree(*provCtx);
        *provCtx = NULL;
        return 0;
    }
    GsProvCtxSet0CoreBioMeth(*provCtx, coreBioMeth);
    GsProvCtxSet0LibCtx(*provCtx, (OSSL_LIB_CTX*)CoreGetLibCtx(handle));
    GsProvCtxSet0Handle(*provCtx, handle);

    *out = gDispatchTable;
    return 1;
}
