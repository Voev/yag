#pragma once
#include <map>
#include <string>
#include <string_view>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <utilities/ossl_pointers.hpp>

namespace ossl
{

class CryptoManager final
{
public:
    ~CryptoManager() noexcept
    {
        for (auto&& [_, prov] : providers_)
        {
            OSSL_PROVIDER_unload(prov);
        }

        OSSL_LIB_CTX_free(ctx_);
    }

    static CryptoManager& getInstance()
    {
        static CryptoManager instance;
        return instance;
    }

    void setProviderPath(std::string_view path)
    {
        OSSL_PROVIDER_set_default_search_path(ctx_, path.data());
    }

    bool loadProvider(const std::string& name)
    {
        auto found = providers_.find(name);
        if (found != providers_.end())
        {
            return false;
        }

        OSSL_PROVIDER* provider = OSSL_PROVIDER_load(ctx_, name.c_str());
        if (!provider)
        {
            throw std::runtime_error("unable to load provider");
        }

        providers_[name] = provider;
        return true;
    }

    bool unloadProvider(const std::string& name)
    {
        auto found = providers_.find(name);
        if (found != providers_.end())
        {
            OSSL_PROVIDER_unload(found->second);
            providers_.erase(found);
            return true;
        }
        return false;
    }

    EvpMdPtr fetchDigest(const char* alg, const char* properties = nullptr)
    {
        return EvpMdPtr{EVP_MD_fetch(ctx_, alg, properties)};
    }

    EvpCipherPtr fetchCipher(const char* alg, const char* properties = nullptr)
    {
        return EvpCipherPtr{EVP_CIPHER_fetch(ctx_, alg, properties)};
    }

    EvpKdfPtr fetchKdf(const char* alg, const char* properties = nullptr)
    {
        return EvpKdfPtr{EVP_KDF_fetch(ctx_, alg, properties)};
    }

    EvpPkeyCtxPtr createKeyContext(const char* alg, const char* properties = nullptr)
    {
        return EvpPkeyCtxPtr{EVP_PKEY_CTX_new_from_name(ctx_, alg, properties)};
    }

    EvpPkeyCtxPtr createKeyContext(EVP_PKEY* pkey, const char* properties = nullptr)
    {
        return EvpPkeyCtxPtr{EVP_PKEY_CTX_new_from_pkey(ctx_, pkey, properties)};
    }

    OSSL_LIB_CTX* getContext() const
    {
        return ctx_;
    }

private:
    CryptoManager()
        : ctx_(OSSL_LIB_CTX_new())
    {
        if (!ctx_)
        {
            throw std::runtime_error("failed to allocate memory");
        }
    }

private:
    std::map<std::string, OSSL_PROVIDER*> providers_;
    OSSL_LIB_CTX* ctx_;
};

} // namespace ossl