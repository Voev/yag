#include <openssl/core_dispatch.h>
#include <gostone/common.h>
#include <gostone/encode/encode_impl.h>

const OSSL_DISPATCH gKuzhyechikEcbFuncs[] = 
{
    { OSSL_FUNC_CIPHER_NEWCTX, FUNC_PTR( alg##_##kbits##_##lcmode##_newctx ) },
    { OSSL_FUNC_CIPHER_FREECTX, FUNC_PTR( alg##_freectx },              
    { OSSL_FUNC_CIPHER_DUPCTX, FUNC_PTR( alg##_dupctx },                
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, FUNC_PTR( ossl_cipher_generic_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, FUNC_PTR( ossl_cipher_generic_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, FUNC_PTR( ossl_cipher_generic_##typ##_update },
    { OSSL_FUNC_CIPHER_FINAL, FUNC_PTR( ossl_cipher_generic_##typ##_final },  
    { OSSL_FUNC_CIPHER_CIPHER, FUNC_PTR( ossl_cipher_generic_cipher },   
    { OSSL_FUNC_CIPHER_GET_PARAMS, FUNC_PTR( alg##_##kbits##_##lcmode##_get_params ) },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, FUNC_PTR( ossl_cipher_generic_get_ctx_params ) },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         
      FUNC_PTR(ossl_cipher_var_keylen_set_ctx_params },                 
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        
      FUNC_PTR(ossl_cipher_generic_gettable_params },                   
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    
      FUNC_PTR(ossl_cipher_generic_gettable_ctx_params },               
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    
     FUNC_PTR(ossl_cipher_var_keylen_settable_ctx_params },             
    { 0, NULL }                                                                
};
