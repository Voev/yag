#pragma once
#include <openssl/ec.h>

typedef struct gs_asymm_key_st GsAsymmKey;

#define INTERPRET_AS_ASYMM_KEY( x ) ( ( GsAsymmKey* )( x ) )
#define INTERPRET_AS_CASYMM_KEY( x ) ( ( const GsAsymmKey* )( x ) )

GsAsymmKey* GsAsymmKeyNew( void );
GsAsymmKey* GsAsymmKeyNewInit( OSSL_LIB_CTX* libCtx, int algorithm );
void GsAsymmKeyFree( GsAsymmKey* key );
void GsAsymmKeySetAlgorithm( GsAsymmKey* key, int algorithm );
void GsAsymmKeySet0LibCtx( GsAsymmKey* key, OSSL_LIB_CTX* ctx );
int GsAsymmKeySet1Group( GsAsymmKey* key, const EC_GROUP* group );
int GsAsymmKeySet1PrivateKey( GsAsymmKey* key, const BIGNUM* privateKey );
int GsAsymmKeySet1PublicKey( GsAsymmKey* key, const EC_POINT* publicKey );

int GsAsymmKeyDecodePublicKey( GsAsymmKey* key, const unsigned char* buf, size_t len );
int GsAsymmKeyGenerate( GsAsymmKey* key );

int GsAsymmKeyGetAlgorithm( const GsAsymmKey* key );
int GsAsymmKeyGetParamset( const GsAsymmKey* key );
int GsAsymmKeyGetKeySize( const GsAsymmKey* key );
int GsAsymmKeyGetKeyBits( const GsAsymmKey* key );
int GsAsymmKeyGetDefaultDigest( const GsAsymmKey* key );

OSSL_LIB_CTX* GsAsymmKeyGet0LibCtx( const GsAsymmKey* key );
const EC_GROUP* GsAsymmKeyGet0Group( const GsAsymmKey* key );
const EC_POINT* GsAsymmKeyGet0PublicKey( const GsAsymmKey* key );
const BIGNUM* GsAsymmKeyGet0PrivateKey( const GsAsymmKey* key );

