#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <gostone/ciphers/cipher_common.h>

GsCipherCtx* GsCipherCtxNew(void)
{
    return OPENSSL_zalloc(sizeof(GsCipherCtx));
}

void GsCipherCtxFree(GsCipherCtx* ctx)
{
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

void GsCipherCtxReset(ossl_unused GsCipherCtx* ctx)
{
}

void GsCipherCtxInit(GsCipherCtx* ctx, size_t keyBits, size_t blockBits,
                     size_t ivBits, unsigned int mode, uint64_t flags,
                     void* provCtx)
{
    OPENSSL_assert(ctx);

    ctx->keyLength = keyBits / 8;
    ctx->ivLength = ivBits / 8;
    ctx->mode = mode;
    ctx->blockSize = blockBits / 8;
    if (NULL != provCtx)
    {
        ctx->libCtx = GsProvCtxGet0LibCtx(provCtx);
    }
}

void* GsCipherDupCtx(void* ctx)
{
    GsCipherCtx* in = INTERPRET_AS_CIPHER_CTX(ctx);
    GsCipherCtx* ret = GsCipherCtxNew();
    if (NULL == ret)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->spec->copyctx(ret, in);
    return ret;
}

static int CipherInit(void* vctx, const unsigned char* key, size_t keyLength,
                      const unsigned char* iv, size_t ivLenght,
                      const OSSL_PARAM params[], int enc)
{
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);

    ctx->num = 0;
    ctx->enc = enc;

    if (NULL != iv && !GsCipherCtxSetIv(ctx, iv, ivLenght))
    {
        return 0;
    }

    if (key != NULL)
    {
        if (keyLength != ctx->keyLength)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!ctx->spec->init(ctx, key, keyLength))
        {
            return 0;
        }
    }
    return GsCipherSetCtxParams(ctx, params);
}

int GsCipherEncryptInit(void* vctx, const unsigned char* key, size_t keyLength,
                        const unsigned char* iv, size_t ivLenght,
                        const OSSL_PARAM params[])
{
    return CipherInit(vctx, key, keyLength, iv, ivLenght, params, 1);
}

int GsCipherDecryptInit(void* vctx, const unsigned char* key, size_t keyLength,
                        const unsigned char* iv, size_t ivLenght,
                        const OSSL_PARAM params[])
{
    return CipherInit(vctx, key, keyLength, iv, ivLenght, params, 0);
}

int GsCipherCtxSetIv(GsCipherCtx* ctx, const unsigned char* iv, size_t ivLength)
{
    OPENSSL_assert(ctx);
    if (ivLength != ctx->ivLength || ivLength > sizeof(ctx->iv))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }
    ctx->ivSetted = 1;
    memcpy(ctx->iv, iv, ivLength);
    return 1;
}

int GsCipherGetParams(OSSL_PARAM params[], unsigned int mode,
                      ossl_unused uint64_t flags, size_t keyBits,
                      size_t blockBits, size_t ivBits)
{
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (NULL != p && !OSSL_PARAM_set_uint(p, mode))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (NULL != p && !OSSL_PARAM_set_size_t(p, keyBits / 8))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (NULL != p && !OSSL_PARAM_set_size_t(p, blockBits / 8))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (NULL != p && !OSSL_PARAM_set_size_t(p, ivBits / 8))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

int GsCipherSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);
    const OSSL_PARAM* p;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL)
    {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    return 1;
}
