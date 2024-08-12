#pragma once
#include <stddef.h>
#include <yag/digests/streebog_defs.h>

typedef struct gs_streebog_ctx_st GsStreebogCtx;

void GsStreebogCtxInit( GsStreebogCtx* ctx );
void GsStreebogCtxUpdate( GsStreebogCtx* ctx, const uint8_t* in, size_t insz );
void GsStreebogCtxFinal( GsStreebogCtx* ctx, uint8_t* out );
int GsStreebogCtxSetDgstSize( GsStreebogCtx* ctx, const size_t sz );
size_t GsStreebogCtxGetDgstSize( GsStreebogCtx* ctx );
size_t GsStreebogCtxGetSize( void );
