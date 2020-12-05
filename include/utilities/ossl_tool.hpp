#pragma once

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <utilities/ossl_pointers.hpp>

namespace ossl
{

inline
EVP_PKEY* GenerateKeyPair( const char* alg, const char* group )
{
    EVP_PKEY* pkey = nullptr;
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr, alg, nullptr ) );
    if( !ctx.get() ||
        !EVP_PKEY_keygen_init( ctx.get() ) ||
        !EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group ) ||
        !EVP_PKEY_keygen( ctx.get(), &pkey ) )
    {
        return nullptr;
    }
    return pkey;
}

inline
EVP_PKEY* GenerateParameters( const char* alg, const char* group )
{
    EVP_PKEY* pkey = nullptr;
    ossl::EvpPkeyCtxPtr ctx( EVP_PKEY_CTX_new_from_name( nullptr, alg, nullptr ) );
    if( !ctx.get() ||
        !EVP_PKEY_paramgen_init( ctx.get() ) ||
        !EVP_PKEY_CTX_ctrl_str( ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group ) ||
        !EVP_PKEY_paramgen( ctx.get(), &pkey ) )
    {
        return nullptr;
    }
    return pkey;
}

} // ossl
