#pragma once

#include <openssl/core.h>

typedef struct gs_prov_ctx_st GsProvCtx;

GsProvCtx* GsProvCtxNew( void );

void GsProvCtxFree( GsProvCtx* ctx );

void GsProvCtxSet0LibCtx( GsProvCtx* ctx, OSSL_LIB_CTX* libCtx );

void GsProvCtxSet0Handle( GsProvCtx* ctx, const OSSL_CORE_HANDLE* handle );

OSSL_LIB_CTX* GsProvCtxGet0LibCtx( GsProvCtx* ctx );

const OSSL_CORE_HANDLE* GsProvCtxGet0Handle( GsProvCtx* ctx );
