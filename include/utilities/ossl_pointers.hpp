#pragma once

#include <memory>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

template< typename T, void ( *f )( T* ) >
struct static_function_deleter
{
    void operator()( T* t ) const
    {
        f( t );
    }
};

#define OSSL_DEFINE_PTR_TYPE( alias, object, deleter )                   \
    using alias##Deleter = static_function_deleter< object, &deleter >; \
    using alias##Ptr     = std::unique_ptr< object, alias##Deleter >

namespace ossl
{

OSSL_DEFINE_PTR_TYPE( LibCtx, OSSL_LIB_CTX, OSSL_LIB_CTX_free );

OSSL_DEFINE_PTR_TYPE( EvpMd, EVP_MD, EVP_MD_free );
OSSL_DEFINE_PTR_TYPE( EvpMdCtx, EVP_MD_CTX, EVP_MD_CTX_free );

OSSL_DEFINE_PTR_TYPE( EvpPkey, EVP_PKEY, EVP_PKEY_free );
OSSL_DEFINE_PTR_TYPE( EvpPkeyCtx, EVP_PKEY_CTX, EVP_PKEY_CTX_free );


} // ossl
