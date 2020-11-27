#pragma once
#include <openssl/ec.h>
#include <openssl/core_dispatch.h>

/* Key management (base) */
OSSL_FUNC_keymgmt_new_fn GsKeyMgmtNew;
OSSL_FUNC_keymgmt_free_fn GsKeyMgmtFree;
OSSL_FUNC_keymgmt_load_fn GsKeyMgmtLoad;
OSSL_FUNC_keymgmt_get_params_fn GsKeyMgmtGetParams;
OSSL_FUNC_keymgmt_gettable_params_fn GsKeyMgmtGettableParams;
OSSL_FUNC_keymgmt_set_params_fn GsKeyMgmtSetParams;
OSSL_FUNC_keymgmt_settable_params_fn GsKeyMgmtSettableParams;
OSSL_FUNC_keymgmt_query_operation_name_fn GsKeyMgmtQueryOperationName;

/* Key management (check) */
OSSL_FUNC_keymgmt_has_fn GsKeyMgmtHas;
OSSL_FUNC_keymgmt_match_fn GsKeyMgmtMatch;
OSSL_FUNC_keymgmt_validate_fn GsKeyMgmtValidate;

/* Key management (export/import) */
OSSL_FUNC_keymgmt_import_fn GsKeyMgmtImport;
OSSL_FUNC_keymgmt_import_types_fn GsKeyMgmtImportTypes;
OSSL_FUNC_keymgmt_export_fn GsKeyMgmtExport;
OSSL_FUNC_keymgmt_export_types_fn GsKeyMgmtExportTypes;

/* Key management (generation) */
OSSL_FUNC_keymgmt_gen_init_fn GsKeyMgmtGenInit;
OSSL_FUNC_keymgmt_gen_set_template_fn GsKeyMgmtGenSetTemplate;
OSSL_FUNC_keymgmt_gen_set_params_fn GsKeyMgmtGenSetParams;
OSSL_FUNC_keymgmt_gen_settable_params_fn GsKeyMgmtGenSettableParams;
OSSL_FUNC_keymgmt_gen_fn GsKeyMgmtGen;
OSSL_FUNC_keymgmt_gen_cleanup_fn GsKeyMgmtGenCleanup;

EC_GROUP* GsGetEcGroup( const OSSL_PARAM* param );
