#include <openssl/core_dispatch.h>
#include <gostone/common.h>
#include <gostone/encode/encode_impl.h>

const OSSL_DISPATCH gGostR341012_256ToPkcs8DerEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesPrivateKeySelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodePrivateKeyToDer)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToPkcs8PemEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesPrivateKeySelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodePrivateKeyToPem)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToSubjPubKeyInfoDerEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesPublicKeySelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodePublicKeyToDer)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToSubjPubKeyInfoPemEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesPublicKeySelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodePublicKeyToPem)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToTypeSpecificDerEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesKeyParamsSelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodeKeyParamsToDer)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToTypeSpecificPemEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsEncoderSettableCtxParams)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION,
     FUNC_PTR(GsEncoderDoesKeyParamsSelection)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderEncodeKeyParamsToPem)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};

const OSSL_DISPATCH gGostR341012_256ToTextEncoderFuncs[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderToTextNewCtx)},
    {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderToTextFreeCtx)},
    {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderToTextEncode)},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},
    {0, NULL}};
