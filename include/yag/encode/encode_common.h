#pragma once
#include <openssl/evp.h>

typedef struct gs_encoder_ctx_st GsEncoderCtx;

const EVP_CIPHER* GsEncoderCtxGet0Cipher(GsEncoderCtx* ctx);

typedef int (*GsEncodeToBioFn)(BIO* out, const void* key, GsEncoderCtx* ctx,
                               OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg);

int GsEncoderCheckSelection(int selection, int selectionMask);

int GsEncoderEncode(GsEncoderCtx* ctx, OSSL_CORE_BIO* cout, const void* keyData,
                    const OSSL_PARAM keyAbstract[], int selection,
                    int selectionMask, OSSL_PASSPHRASE_CALLBACK* cb,
                    void* cbArg, GsEncodeToBioFn encoderToBio);
