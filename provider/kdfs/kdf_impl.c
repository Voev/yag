#include <gostone/common.h>
#include <gostone/kdfs/kdf_tree12_256.h>

const OSSL_DISPATCH gKdfTree12_256Funcs[] = {
    {OSSL_FUNC_KDF_NEWCTX, FUNC_PTR(GsKdfTree12_256New)},
    {OSSL_FUNC_KDF_FREECTX, FUNC_PTR(GsKdfTree12_256Free)},
    {OSSL_FUNC_KDF_RESET, FUNC_PTR(GsKdfTree12_256Reset)},
    {OSSL_FUNC_KDF_DERIVE, FUNC_PTR(GsKdfTree12_256Derive)},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
     FUNC_PTR(GsKdfTree12_256SettableCtxParams)},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, FUNC_PTR(GsKdfTree12_256SetCtxParams)},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
     FUNC_PTR(GsKdfTree12_256GettableCtxParams)},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, FUNC_PTR(GsKdfTree12_256GetCtxParams)},
    {0, NULL}};
