#pragma once

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <utilities/ossl_pointers.hpp>
#include <utilities/crypto_manager.hpp>

namespace ossl
{

inline EvpPkeyPtr GenerateKeyPair(const char* alg, const char* group)
{
    EVP_PKEY* pkey = nullptr;
    auto ctx = CryptoManager::getInstance().createKeyContext(alg);
    if (!ctx.get() || !EVP_PKEY_keygen_init(ctx.get()) ||
        !EVP_PKEY_CTX_ctrl_str(ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group) ||
        !EVP_PKEY_keygen(ctx.get(), &pkey))
    {
        return nullptr;
    }
    return EvpPkeyPtr{pkey};
}

inline EvpPkeyPtr GenerateParameters(const char* alg, const char* group)
{
    EVP_PKEY* pkey = nullptr;
    auto ctx = CryptoManager::getInstance().createKeyContext(alg);
    if (!ctx.get() || !EVP_PKEY_paramgen_init(ctx.get()) ||
        !EVP_PKEY_CTX_ctrl_str(ctx.get(), OSSL_PKEY_PARAM_GROUP_NAME, group) ||
        !EVP_PKEY_paramgen(ctx.get(), &pkey))
    {
        return nullptr;
    }
    return EvpPkeyPtr{pkey};
}

} // namespace ossl