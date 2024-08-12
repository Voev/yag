#include <string.h>
#include <yag/digests/streebog_defs.h>
#include <yag/digests/streebog_core.h>

struct gs_streebog_ctx_st
{
    union
    {
        uint8_t u8[BlockLengthInBytes];
        uint64_t u64[BlockLengthInUInt64];
    } buffer;

    uint64_t h[BlockLengthInUInt64];
    uint64_t N[BlockLengthInUInt64];
    uint64_t sigma[BlockLengthInUInt64];
    uint64_t digest[BlockLengthInUInt64];
    size_t bufferSize;
    size_t digestSize;
};

static inline void doPadding(uint64_t buffer[], size_t bufferSize)
{
    size_t appendIndex = bufferSize / sizeof(uint64_t);
    size_t appendPosition = bufferSize % sizeof(uint64_t);

    for (size_t i = appendIndex + 1; i < BlockLengthInUInt64; ++i)
    {
        buffer[i] = 0;
    }
    uint64_t appendBit = UINT64_C(1) << (8 * appendPosition);
    buffer[appendIndex] &= appendBit - 1;
    buffer[appendIndex] |= appendBit;
}

static inline void doAdd(uint64_t r[], const uint64_t x[], const uint64_t y[])
{
    for (uint8_t carry = 0, i = 0; i < BlockLengthInUInt64; ++i)
    {
        const uint64_t left = x[i];
        uint64_t sum;

        sum = left + y[i] + carry;
        if (sum != left)
        {
            carry = (sum < left);
            r[i] = sum;
        }
    }
}

static inline void doXor(uint64_t r[], const uint64_t x[], const uint64_t y[])
{
    for (size_t i = 0; i < BlockLengthInUInt64; ++i)
    {
        r[i] = x[i] ^ y[i];
    }
}

static inline void doLPS(uint64_t r[], const uint64_t x[], const uint64_t y[])
{
    uint64_t a[BlockLengthInUInt64] = {0};
    doXor(a, x, y);

    for (size_t i = 0; i < BlockLengthInUInt64; ++i)
    {
        r[i] = Ax[0][(a[0] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[1][(a[1] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[2][(a[2] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[3][(a[3] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[4][(a[4] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[5][(a[5] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[6][(a[6] >> (i << 3)) & 0xFF];
        r[i] ^= Ax[7][(a[7] >> (i << 3)) & 0xFF];
    }
}

void g(uint64_t h[], const uint64_t N[], const uint64_t m[])
{
    uint64_t K[BlockLengthInUInt64] = {0};
    uint64_t Ki[BlockLengthInUInt64] = {0};

    /*
     * $K := LPS(h \xor N)
     */
    doLPS(K, h, N);

    /*
     * E(K, m) := X[K_{13}]LPSX[K_{12}]...LPSX[K_1](m)
     * K_1 := K
     * $K := LPSX[K_1](m)
     */
    memcpy(Ki, K, BlockLengthInBytes);
    doLPS(K, Ki, m);

    for (int i = 0; i < NumberOfRounds - 1; ++i)
    {
        /* K_2 := LPS(K_1 \xor C_1) etc. */
        doLPS(Ki, Ki, &C[i * BlockLengthInUInt64]);
        /* $K := LPSX[K_2]LPSX[K_1](m) etc. */
        doLPS(K, Ki, K);
    }

    /* Last round */
    doLPS(Ki, Ki, &C[(NumberOfRounds - 1) * BlockLengthInUInt64]);
    doXor(K, Ki, K);

    /* E(K, m) done */
    doXor(K, K, h);
    doXor(h, K, m);
}

void doStage2(GsStreebogCtx* ctx, const void* data)
{
    /*
     * M := M' || m, m \in V_{512} (last 512 bits of $data)
     * h := g(h, m, N)
     * N := Vec_{512} ( Int_{512}(N) \boxplus 512 )
     * sigma := Vec_{512} ( Int_{512}(sigma) \boxplus  Int_{512}(m) )
     * M := M'
     */
    uint64_t m[BlockLengthInUInt64] = {0};
    memcpy(m, data, sizeof(m));

    g(ctx->h, ctx->N, m);
    doAdd(ctx->N, ctx->N, gConst512);
    doAdd(ctx->sigma, ctx->sigma, m);
}

void doStage3(GsStreebogCtx* ctx)
{
    uint64_t buffer[BlockLengthInUInt64] = {0};
    memcpy(buffer, ctx->buffer.u64, sizeof(buffer));

    memcpy(ctx->buffer.u64, buffer, sizeof(buffer));
    memset(buffer, 0x00, sizeof(buffer));

    buffer[0] = ctx->bufferSize << 3;

    doPadding(ctx->buffer.u64, ctx->bufferSize);

    g(ctx->h, ctx->N, ctx->buffer.u64);

    /*
     * N     := Vec_512(Int_512(N) \boxplus |M|)
     * Sigma := Vec_512(Int_512(Sigma) \boxplus Int_512(m))
     */
    doAdd(ctx->N, ctx->N, buffer);
    doAdd(ctx->sigma, ctx->sigma, ctx->buffer.u64);

    g(ctx->h, gConst0, ctx->N);
    g(ctx->h, gConst0, ctx->sigma);

    memcpy(ctx->digest, ctx->h, sizeof(ctx->h));
}

void GsStreebogCtxInit(GsStreebogCtx* ctx)
{
    /* Stage 1:
     *    h = IV
     *    N = 0^{512} \in V_{512}
     *    sigma = 0^{512} \in V_{512}
     */
    if (ctx->digestSize == Streebog256LengthInBytes)
    {
        memset(ctx->h, 0x01, BlockLengthInBytes);
    }
}

void GsStreebogCtxUpdate(GsStreebogCtx* ctx, const uint8_t* data,
                         size_t dataSize)
{
    size_t chunkSize;

    /* Stage 2: do until |M| < 512 bits, M = $data */
    while (BlockLengthInBytes < dataSize && !ctx->bufferSize)
    {
        doStage2(ctx, data);

        data += BlockLengthInBytes;
        dataSize -= BlockLengthInBytes;
    }

    while (dataSize)
    {
        chunkSize = BlockLengthInBytes - ctx->bufferSize;
        if (chunkSize > dataSize)
        {
            chunkSize = dataSize;
        }

        memcpy(&ctx->buffer.u8[ctx->bufferSize], data, chunkSize);
        ctx->bufferSize += chunkSize;

        data += chunkSize;
        dataSize -= chunkSize;

        if (BlockLengthInBytes == ctx->bufferSize)
        {
            doStage2(ctx, ctx->buffer.u64);
            ctx->bufferSize = 0;
        }
    }
}

void GsStreebogCtxFinal(GsStreebogCtx* ctx, uint8_t* digest)
{
    doStage3(ctx);
    ctx->bufferSize = 0;

    if (ctx->digestSize == Streebog256LengthInBytes)
    {
        memcpy(digest, &ctx->digest[BlockLengthInUInt64 / 2], ctx->digestSize);
    }
    else
    {
        memcpy(digest, ctx->digest, ctx->digestSize);
    }
}

int GsStreebogCtxSetDgstSize(GsStreebogCtx* ctx, const size_t digestSize)
{
    if (ctx)
    {
        ctx->digestSize = digestSize;
        return 1;
    }
    return 0;
}

size_t GsStreebogCtxGetDgstSize(GsStreebogCtx* ctx)
{
    return ctx ? ctx->digestSize : 0;
}

size_t GsStreebogCtxGetSize(void)
{
    return sizeof(GsStreebogCtx);
}
