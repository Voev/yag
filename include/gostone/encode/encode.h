#pragma once

typedef struct gs_encoder_ctx_st GsEncoderCtx;

const EVP_CIPHER* GsEncoderCtxGet0Cipher( GsEncoderCtx* ctx );

typedef int ( *GsEncodeKeyToBioFn )( BIO* out, const void* key, int keyNid, 
                                     GsEncoderCtx* ctx );

int GsEncodePrivateKeyToDerBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx );

int GsEncodePrivateKeyToPemBio( BIO* out, const void* key, int keyNid, 
                                GsEncoderCtx* ctx );

int GsEncodePublicKeyToDerBio( BIO* out, const void* key, int keyNid, 
                               GsEncoderCtx* ctx );

int GsEncodePublicKeyToPemBio( BIO* out, const void* key, int keyNid, 
                               GsEncoderCtx* ctx );

typedef int ( *GsEncodeParamsToBioFn )( BIO* out, const void* key, int keyNid );


int GsPrepareParams( const void* key, int keyNid, ASN1_STRING** params );

int GsEncodeParamsToDerBio( BIO* out, const void* key, int keyNid );

int GsEncodeParamsToPemBio( BIO* out, const void* key, int keyNid );
