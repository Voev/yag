#pragma once
#include <openssl/evp.h>
#include <openssl/core_names.h>

typedef struct gs_cipher_ctx_st GsCipherCtx;
typedef struct gs_cipher_specific_st GsCipherSpec;
#define INTERPRET_AS_CIPHER_CTX(x) ((GsCipherCtx*)x)

struct gs_cipher_ctx_st
{
    BUF_MEM* key;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int ivSetted;
    int enc;
    int num;
    size_t ivLength;
    size_t keyLength;
    size_t blockSize;
    unsigned int mode;
    const GsCipherSpec* spec;
    OSSL_LIB_CTX* libCtx; // used for rand
};

struct gs_cipher_specific_st
{
    int (*init)(GsCipherCtx* ctx, const uint8_t* key, size_t keyLength);
    int (*cipher)(GsCipherCtx* dat, unsigned char* out, const unsigned char* in,
                  size_t length);
    void (*copyctx)(GsCipherCtx* dst, const GsCipherCtx* src);
};

GsCipherCtx* GsCipherCtxNew(void);
void GsCipherCtxReset(GsCipherCtx* ctx);

OSSL_FUNC_cipher_encrypt_init_fn GsCipherEncryptInit;
OSSL_FUNC_cipher_decrypt_init_fn GsCipherDecryptInit;
OSSL_FUNC_cipher_dupctx_fn GsCipherDupCtx;

void GsCipherCtxInit(GsCipherCtx* ctx, size_t keyBits, size_t blockBits,
                     size_t ivBits, unsigned int mode, uint64_t flags,
                     void* provCtx);

int GsCipherCtxSetIv(GsCipherCtx* ctx, const unsigned char* iv,
                     size_t ivLength);

#define CIPHER_DEFAULT_GETTABLE_PARAMS_START(name)                             \
    static const OSSL_PARAM g##name##KnownGettableParams[] = {                 \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),                         \
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),                     \
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),                      \
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),

#define CIPHER_DEFAULT_GETTABLE_PARAMS_END(name)                               \
    OSSL_PARAM_END                                                             \
    }                                                                          \
    ;
int GsCipherGetParams(OSSL_PARAM params[], unsigned int mode,
                      ossl_unused uint64_t flags, size_t keyBits,
                      size_t blockBits, size_t ivBits);

#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(name)                         \
    static const OSSL_PARAM g##name##KnownSettableCtxParams[] = {              \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                      \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
    }                                                                          \
    ;
int GsCipherSetCtxParams(void* vctx, const OSSL_PARAM params[]);
