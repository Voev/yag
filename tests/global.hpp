#pragma once
#include <memory>
#include <openssl/crypto.h>
#include <gtest/gtest.h>

namespace ossl
{

class LibCtx
{
public:
    static OSSL_LIB_CTX* Get0();

    ~LibCtx();

    LibCtx( LibCtx const& ) = delete;
    LibCtx& operator=( LibCtx const& ) = delete;

    LibCtx( LibCtx const&& ) = delete;
    LibCtx operator=( LibCtx const&& ) = delete;

private:
    LibCtx() = default;

private:
    static OSSL_LIB_CTX* ctx_;
};

} // ossl
