#pragma once
#include <openssl/core_dispatch.h>

int GsPrepareParams( const void* key, ASN1_STRING** params );
