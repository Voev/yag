#pragma once

#include <gostone/provider_ctx.h>

BIO* GsProvBioNewFromCoreBio(GsProvCtx* provCtx, OSSL_CORE_BIO* coreBio);
