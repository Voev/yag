#pragma once
#include <yag/provider_ctx.h>

void GsErrorRaise(GsProvCtx* ctx, const char* file, int line, const char* func, int errnum,
                  const char* fmt, ...);

#define ErrRaiseData(ctx, reason, format, ...)                                                     \
    do                                                                                             \
    {                                                                                              \
        GsErrorRaise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, (reason), (format),          \
                     ##__VA_ARGS__);                                                               \
    } while (0)

#define ErrRaise(ctx, reason) ErrRaiseData((ctx), (reason), NULL)

int GsSetErrorMark(GsProvCtx* ctx);

int GsClearLastErrorMark(GsProvCtx* ctx);

int GsPopErrorToMark(GsProvCtx* ctx);
