#pragma once
#include <openssl/core_dispatch.h>

OSSL_FUNC_encoder_newctx_fn GsEncoderNewCtx;
OSSL_FUNC_encoder_freectx_fn GsEncoderFreeCtx;

OSSL_FUNC_encoder_newctx_fn GsEncoderToTextNewCtx;
OSSL_FUNC_encoder_freectx_fn GsEncoderToTextFreeCtx;

OSSL_FUNC_encoder_does_selection_fn GsEncoderDoesPrivateKeySelection;
OSSL_FUNC_encoder_does_selection_fn GsEncoderDoesPublicKeySelection;
OSSL_FUNC_encoder_does_selection_fn GsEncoderDoesKeyParamsSelection;

OSSL_FUNC_encoder_get_params_fn GsEncoderGetPrivateKeyParams256ToDer;
OSSL_FUNC_encoder_get_params_fn GsEncoderGetPrivateKeyParams256ToPem;
OSSL_FUNC_encoder_get_params_fn GsEncoderGetPublicKeyParams256ToDer;
OSSL_FUNC_encoder_get_params_fn GsEncoderGetPublicKeyParams256ToPem;
OSSL_FUNC_encoder_get_params_fn GsEncoderGetKeyParams256ToDer;
OSSL_FUNC_encoder_get_params_fn GsEncoderGetKeyParams256ToPem;
OSSL_FUNC_encoder_get_params_fn GsEncoderToTextGetAllKeyParams256;

OSSL_FUNC_encoder_gettable_params_fn GsEncoderGettableParams;
OSSL_FUNC_encoder_gettable_params_fn GsEncoderToTextGettableParams;

OSSL_FUNC_encoder_set_ctx_params_fn GsEncoderSetCtxParams;
OSSL_FUNC_encoder_settable_ctx_params_fn GsEncoderSettableCtxParams;

OSSL_FUNC_encoder_encode_fn GsEncoderEncodePrivateKeyToDer;
OSSL_FUNC_encoder_encode_fn GsEncoderEncodePrivateKeyToPem;
OSSL_FUNC_encoder_encode_fn GsEncoderEncodePublicKeyToDer;
OSSL_FUNC_encoder_encode_fn GsEncoderEncodePublicKeyToPem;
OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKeyParamsToDer;
OSSL_FUNC_encoder_encode_fn GsEncoderEncodeKeyParamsToPem;
OSSL_FUNC_encoder_encode_fn GsEncoderToTextEncode;

OSSL_FUNC_encoder_import_object_fn GsEncoderImportObject;
OSSL_FUNC_encoder_free_object_fn GsEncoderFreeObject;