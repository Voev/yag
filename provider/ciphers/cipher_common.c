#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <gostone/provider_ctx.h>
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
                     size_t ivBits, unsigned int mode,
                     ossl_unused uint64_t flags, const GsCipherSpec* spec,
                     void* provCtx)
{
    OPENSSL_assert(ctx);

    ctx->keyLength = keyBits / 8;
    ctx->ivLength = ivBits / 8;
    ctx->mode = mode;
    ctx->blockSize = blockBits / 8;
    ctx->spec = spec;
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

size_t ossl_cipher_fillblock(unsigned char* buf, size_t* buflen,
                             size_t blocksize, const unsigned char** in,
                             size_t* inlen)
{
    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *buflen;

    OPENSSL_assert(*buflen <= blocksize);
    OPENSSL_assert(blocksize > 0 && (blocksize & (blocksize - 1)) == 0);

    if (*inlen < bufremain)
        bufremain = *inlen;
    memcpy(buf + *buflen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *buflen += bufremain;

    return *inlen & blockmask;
}

int ossl_cipher_trailingdata(unsigned char* buf, size_t* buflen,
                             size_t blocksize, const unsigned char** in,
                             size_t* inlen)
{
    if (*inlen == 0)
        return 1;

    if (*buflen + *inlen > blocksize)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(buf + *buflen, *in, *inlen);
    *buflen += *inlen;
    *inlen = 0;

    return 1;
}

int GsCipherBlockUpdate(void* vctx, unsigned char* out, size_t* outl,
                        size_t outsize, const unsigned char* in, size_t inl)
{
    size_t outlint = 0;
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);
    size_t blksz = ctx->blockSize;
    size_t nextblocks;

    if (ctx->bufferSize != 0)
        nextblocks = ossl_cipher_fillblock(ctx->buffer, &ctx->bufferSize, blksz,
                                           &in, &inl);
    else
        nextblocks = inl & ~(blksz - 1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufferSize == blksz && (ctx->enc || inl > 0 || !ctx->pad))
    {
        if (outsize < blksz)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->spec->cipher(ctx, out, ctx->buffer, blksz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufferSize = 0;
        outlint = blksz;
        out += blksz;
    }
    if (nextblocks > 0)
    {
        if (!ctx->enc && ctx->pad && nextblocks == inl)
        {
            if (inl < blksz)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= blksz;
        }
        outlint += nextblocks;
        if (outsize < outlint)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    }
    if (nextblocks > 0)
    {
        if (!ctx->spec->cipher(ctx, out, in, nextblocks))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0 && !ossl_cipher_trailingdata(ctx->buffer, &ctx->bufferSize,
                                              blksz, &in, &inl))
    {
        /* ERR_raise already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

/* Pad the final block for encryption */
void ossl_cipher_padblock(unsigned char* buf, size_t* buflen, size_t blocksize)
{
    size_t i;
    unsigned char pad = (unsigned char)(blocksize - *buflen);

    for (i = *buflen; i < blocksize; i++)
        buf[i] = pad;
}

int ossl_cipher_unpadblock(unsigned char* buf, size_t* buflen, size_t blocksize)
{
    size_t pad, i;
    size_t len = *buflen;

    if (len != blocksize)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle.
     */
    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
        return 0;
    }
    for (i = 0; i < pad; i++)
    {
        if (buf[--len] != pad)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
    }
    *buflen = len;
    return 1;
}

int GsCipherBlockFinal(void* vctx, unsigned char* out, size_t* outl,
                       size_t outsize)
{
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);
    size_t blksz = ctx->blockSize;

    if (ctx->enc)
    {
        if (ctx->pad)
        {
            ossl_cipher_padblock(ctx->buffer, &ctx->bufferSize, blksz);
        }
        else if (ctx->bufferSize == 0)
        {
            *outl = 0;
            return 1;
        }
        else if (ctx->bufferSize != blksz)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < blksz)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->spec->cipher(ctx, out, ctx->buffer, blksz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufferSize = 0;
        *outl = blksz;
        return 1;
    }

    /* Decrypting */
    if (ctx->bufferSize != blksz)
    {
        if (ctx->bufferSize == 0 && !ctx->pad)
        {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (!ctx->spec->cipher(ctx, ctx->buffer, ctx->buffer, blksz))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->pad &&
        !ossl_cipher_unpadblock(ctx->buffer, &ctx->bufferSize, blksz))
    {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < ctx->bufferSize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, ctx->buffer, ctx->bufferSize);
    *outl = ctx->bufferSize;
    ctx->bufferSize = 0;
    return 1;
}

int GsCipherCipher(void* vctx, unsigned char* out, size_t* outLength,
                   size_t outSize, const unsigned char* in, size_t inLength)
{
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);

    if (outSize < inLength)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->spec->cipher(ctx, out, in, inLength))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outLength = inLength;
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

int GsCipherGetCtxParams(void* vctx, OSSL_PARAM params[])
{
    GsCipherCtx* ctx = INTERPRET_AS_CIPHER_CTX(vctx);
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivLength))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    /*
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivLength) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivLength))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }*/
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLength) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivLength))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keyLength))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    /*
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }*/
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

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL)
    {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
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
