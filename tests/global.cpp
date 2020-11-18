#include "global.hpp"

namespace ossl
{

OSSL_LIB_CTX* LibCtx::ctx_ = nullptr;

OSSL_LIB_CTX* LibCtx::Get0()
{
    if( !ctx_ )
    {
        ctx_ = OSSL_LIB_CTX_new();
    }
    return ctx_;
}

LibCtx::~LibCtx()
{
    OSSL_LIB_CTX_free( ctx_ );
}

} // ossl
