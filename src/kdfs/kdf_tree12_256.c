#include <string.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <yag/kdfs/kdf_tree12_256.h>
#include <yag/provider_ctx.h>
#include <yag/buffer.h>

#pragma message "make set constant"

typedef struct gs_kdf_tree_st
{
    void* provCtx;
    BUF_MEM* label;
    BUF_MEM* secret;
    BUF_MEM* seed;
    size_t counter;
} GsKdfTree;

static int GsKdfTree12_256(BUF_MEM* secret, BUF_MEM* label, BUF_MEM* seed,
                           size_t R, unsigned char* key, size_t keyLen);

void* GsKdfTree12_256New(void* provCtx)
{
    GsKdfTree* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        goto err;
    }
    ctx->secret = BUF_MEM_new_ex(BUF_MEM_FLAG_SECURE);
    ctx->label = BUF_MEM_new();
    ctx->seed = BUF_MEM_new();
    if (ctx->secret == NULL || ctx->label == NULL || ctx->seed == NULL)
    {
        goto err;
    }
    ctx->provCtx = provCtx;
    return ctx;
err:
    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    GsKdfTree12_256Free(ctx);
    return NULL;
}

void GsKdfTree12_256Free(void* vctx)
{
    GsKdfTree* ctx = (GsKdfTree*)vctx;
    if (ctx)
    {
        GsKdfTree12_256Reset(ctx);
        OPENSSL_free(ctx);
    }
}

void GsKdfTree12_256Reset(void* vctx)
{
    GsKdfTree* ctx = (GsKdfTree*)vctx;
    if (ctx)
    {
        void* provCtx = ctx->provCtx;
        BUF_MEM_free(ctx->label);
        BUF_MEM_free(ctx->secret);
        BUF_MEM_free(ctx->seed);
        memset(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

int GsKdfTree12_256Derive(void* vctx, unsigned char* key, size_t keyLen,
                          const OSSL_PARAM params[])
{

    GsKdfTree* ctx = (GsKdfTree*)vctx;

    if (!GsKdfTree12_256SetCtxParams(ctx, params))
    {
        return 0;
    }
    if (BUF_MEM_empty(ctx->secret))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        return 0;
    }
    if (BUF_MEM_empty(ctx->label))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }
    if (BUF_MEM_empty(ctx->seed))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return 0;
    }
    return GsKdfTree12_256(ctx->secret, ctx->label, ctx->seed, 1, key, keyLen);
}

int GsKdfTree12_256SetCtxParams(void* vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM* p;
    GsKdfTree* ctx = (GsKdfTree*)vctx;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL);
    if (p != NULL)
    {
        size_t usedLen = 0;

        if (!OSSL_PARAM_get_octet_string(p, NULL, 0, &usedLen) ||
            !BUF_MEM_grow_clean(ctx->label, usedLen) ||
            !OSSL_PARAM_get_octet_string(p, (void**)&ctx->label->data, usedLen,
                                         NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
    if (p != NULL)
    {
        size_t usedLen = 0;

        if (!OSSL_PARAM_get_octet_string(p, NULL, 0, &usedLen) ||
            !BUF_MEM_grow_clean(ctx->secret, usedLen) ||
            !OSSL_PARAM_get_octet_string(p, (void**)&ctx->secret->data, usedLen,
                                         NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
    if (p != NULL)
    {
        size_t usedLen = 0;

        if (!OSSL_PARAM_get_octet_string(p, NULL, 0, &usedLen) ||
            !BUF_MEM_grow_clean(ctx->seed, usedLen) ||
            !OSSL_PARAM_get_octet_string(p, (void**)&ctx->seed->data, usedLen,
                                         NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    return 1;
}

const OSSL_PARAM* GsKdfTree12_256SettableCtxParams(ossl_unused void* ctx,
                                                   ossl_unused void* provCtx)
{
    static const OSSL_PARAM gKnownSettableCtxParams[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_CONSTANT, NULL, 0),
        OSSL_PARAM_END};
    return gKnownSettableCtxParams;
}

int GsKdfTree12_256GetCtxParams(ossl_unused void* vctx, OSSL_PARAM params[])
{
    OSSL_PARAM* p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL)
    {
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    }
    return -2;
}

const OSSL_PARAM* GsKdfTree12_256GettableCtxParams(ossl_unused void* ctx,
                                                   ossl_unused void* provCtx)
{
    static const OSSL_PARAM gKnownGettableCtxParams[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL), OSSL_PARAM_END};
    return gKnownGettableCtxParams;
}

int GsKdfTree12_256(BUF_MEM* secret, BUF_MEM* label, BUF_MEM* seed, size_t R,
                    unsigned char* key, size_t keyLen)
{
    OSSL_PARAM param[] = {OSSL_PARAM_END, OSSL_PARAM_END};
    const char* alg = SN_id_GostR3411_2012_256;
    unsigned char* LBytes = NULL;
    unsigned char* ptr;
    EVP_MAC* mac = NULL;
    EVP_MD* md;
    uint32_t L;
    size_t iter, iters, LSize = 4;
    int blockSize, ret = 0;

    param[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)alg, 0);
    md = EVP_MD_fetch(NULL, alg, NULL);
    if (md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
        goto end;
    }
    blockSize = EVP_MD_size(md);

    if (key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }
    if (keyLen == 0 || keyLen % blockSize != 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_KEY_SIZE);
        goto end;
    }
    iters = keyLen / blockSize;
    L = htonl(keyLen * 8);

    for (LBytes = (unsigned char*)&L; *LBytes == 0; ++LBytes)
        LSize--;

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if (mac == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_MAC_TYPE);
        goto end;
    }

    for (iter = 1, ptr = key; iter <= iters; ++iter)
    {
        const uint8_t zeroByte = 0x00;
        size_t outSize = 0;

        uint32_t i = htonl(iter);
        unsigned char* RBytes = (unsigned char*)&i + (4 - R);

        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (ctx == NULL ||
            !EVP_MAC_init(ctx, BUF_MEM_data(secret), BUF_MEM_size(secret),
                          param) ||
            !EVP_MAC_update(ctx, RBytes, R) ||
            !EVP_MAC_update(ctx, BUF_MEM_data(label), BUF_MEM_size(label)) ||
            !EVP_MAC_update(ctx, &zeroByte, sizeof(zeroByte)) ||
            !EVP_MAC_update(ctx, BUF_MEM_data(seed), BUF_MEM_size(seed)) ||
            !EVP_MAC_update(ctx, LBytes, LSize) ||
            !EVP_MAC_final(ctx, ptr, &outSize, blockSize))
        {
            EVP_MAC_CTX_free(ctx);
            goto end;
        }
        EVP_MAC_CTX_free(ctx);
        ptr += outSize;
    }
    ret = 1;
end:
    EVP_MAC_free(mac);
    EVP_MD_free(md);
    return ret;
}
