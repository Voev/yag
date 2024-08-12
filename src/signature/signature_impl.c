#include <openssl/core_dispatch.h>
#include <yag/signature/signature_impl.h>
#include <yag/common.h>
#include <yag/implementations.h>

const OSSL_DISPATCH gGostR341012_SignatureFunctions[] = 
{
    { OSSL_FUNC_SIGNATURE_NEWCTX, FUNC_PTR( GsSignatureNewCtx ) },
    { OSSL_FUNC_SIGNATURE_FREECTX, FUNC_PTR( GsSignatureFreeCtx ) },
    { OSSL_FUNC_SIGNATURE_DUPCTX, FUNC_PTR( GsSignatureDupCtx ) },
    
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, FUNC_PTR( GsSignatureSignVerifyInit ) },
    { OSSL_FUNC_SIGNATURE_SIGN, FUNC_PTR( GsSignatureSign ) },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, FUNC_PTR( GsSignatureSignVerifyInit ) },
    { OSSL_FUNC_SIGNATURE_VERIFY, FUNC_PTR( GsSignatureVerify ) },
    
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, FUNC_PTR( GsSignatureDigestSignVerifyInit ) },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, FUNC_PTR( GsSignatureDigestSignVerifyUpdate ) },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, FUNC_PTR( GsSignatureDigestSignFinal ) },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, FUNC_PTR( GsSignatureDigestSignVerifyInit ) },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, FUNC_PTR( GsSignatureDigestSignVerifyUpdate ) },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, FUNC_PTR( GsSignatureDigestVerifyFinal ) },
    
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, FUNC_PTR( GsSignatureGettableCtxParams ) },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, FUNC_PTR( GsSignatureGettableCtxMdParams ) },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, FUNC_PTR( GsSignatureGetCtxParams ) },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, FUNC_PTR( GsSignatureGetCtxMdParams ) },
    
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, FUNC_PTR( GsSignatureSetCtxParams ) },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, FUNC_PTR( GsSignatureSettableCtxParams ) },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, FUNC_PTR( GsSignatureSetCtxMdParams ) },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, FUNC_PTR( GsSignatureSettableCtxMdParams ) },
    { 0, NULL }
};
