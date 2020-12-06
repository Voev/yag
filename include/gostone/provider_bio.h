#pragma once

#include <gostone/provider_ctx.h>

int GsProvBioFromDispatch( const OSSL_DISPATCH* funcs );

BIO_METHOD* GsProvBioInitBioMethod(void);

BIO* GsProvBioNewFromCoreBio(GsProvCtx* provCtx, OSSL_CORE_BIO* coreBio);
