#pragma once

#include <openssl/bio.h>
#include <openssl/core.h>

typedef struct gs_prov_ctx_st GsProvCtx;

#define INTERPRET_AS_PROV_CTX( x ) (( GsProvCtx* )( x ))

GsProvCtx* GsProvCtxNew( void );

void GsProvCtxFree( GsProvCtx* ctx );

void GsProvCtxSet0LibCtx( GsProvCtx* ctx, OSSL_LIB_CTX* libCtx );

void GsProvCtxSet0Handle( GsProvCtx* ctx, const OSSL_CORE_HANDLE* handle );

void GsProvCtxSet0CoreBioMeth( GsProvCtx* ctx, BIO_METHOD* coreBioMeth );

OSSL_LIB_CTX* GsProvCtxGet0LibCtx( GsProvCtx* ctx );

const OSSL_CORE_HANDLE* GsProvCtxGet0Handle( GsProvCtx* ctx );

const BIO_METHOD* GsProvCtxGet0CoreBioMeth( GsProvCtx* ctx );
