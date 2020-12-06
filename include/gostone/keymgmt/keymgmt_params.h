#pragma once
#include <openssl/ec.h>

EC_GROUP* GsGetEcGroup( const OSSL_PARAM* param );
