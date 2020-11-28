#include <openssl/core_dispatch.h>
#include <gostone/common.h>
#include <gostone/keymgmt/keymgmt.h>

const OSSL_DISPATCH gGostR341012_256Funcs[] =
{
    { OSSL_FUNC_KEYMGMT_NEW, FUNC_PTR( GsKeyMgmtNew ) },
    { OSSL_FUNC_KEYMGMT_FREE, FUNC_PTR( GsKeyMgmtFree ) },
    { OSSL_FUNC_KEYMGMT_LOAD, FUNC_PTR( GsKeyMgmtLoad ) },
    { OSSL_FUNC_KEYMGMT_MATCH, FUNC_PTR( GsKeyMgmtMatch ) },
    { OSSL_FUNC_KEYMGMT_HAS, FUNC_PTR( GsKeyMgmtHas ) },
    { OSSL_FUNC_KEYMGMT_VALIDATE, FUNC_PTR( GsKeyMgmtValidate ) },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, FUNC_PTR( GsKeyMgmtGetParams ) },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, FUNC_PTR( GsKeyMgmtGettableParams ) },
    { OSSL_FUNC_KEYMGMT_IMPORT, FUNC_PTR( GsKeyMgmtImport ) },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, FUNC_PTR( GsKeyMgmtImportTypes ) },
    { OSSL_FUNC_KEYMGMT_EXPORT, FUNC_PTR( GsKeyMgmtExport ) },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, FUNC_PTR( GsKeyMgmtExportTypes ) },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, FUNC_PTR( GsKeyMgmtGenInit ) },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, FUNC_PTR( GsKeyMgmtGenSetTemplate ) },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, FUNC_PTR( GsKeyMgmtGenSetParams ) },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, FUNC_PTR( GsKeyMgmtGenSettableParams ) },
    { OSSL_FUNC_KEYMGMT_GEN, FUNC_PTR( GsKeyMgmtGen ) },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, FUNC_PTR( GsKeyMgmtGenCleanup ) },
    { 0, NULL }
};