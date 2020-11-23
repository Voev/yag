#pragma once
#include <openssl/ec.h>
#include <openssl/core.h>

int GsKeyMgmtMatch( const void* keyDataA, const void* keyDataB, int selection );
int GsKeyMgmtHas( const void* keyData, int selection );
int GsKeyMgmtValidate( const void* keyData, int selection );

void* GsKeyMgmtGenInit( void* provCtx, int selection );
int GsKeyMgmtGenSetTemplate( void* genctx, void* templ );
int GsKeyMgmtGenSetParams( void* genCtx, const OSSL_PARAM params[] );
const OSSL_PARAM* GsKeyMgmtGenSettableParams( void* provCtx );
void* GsKeyMgmtGen( void* genCtx, OSSL_CALLBACK* cb, void* cbArg );
void GsKeyMgmtGenCleanup( void* genCtx );

EC_GROUP* GsGetEcGroup( const OSSL_PARAM* param );
