#pragma once
#include <openssl/provider.h>

namespace ossl
{

class LibCtx
{

    OSSL_PROVIDER* prov;
};


}