#pragma once
#include <openssl/asn1.h>
#include <openssl/pem.h> 
#include <openssl/ossl_typ.h>

typedef struct
{
    ASN1_OBJECT* keyParams;
    ASN1_OBJECT* hashParams;
    ASN1_OBJECT* cipherParams;
}
GostKeyParams;
DECLARE_ASN1_FUNCTIONS( GostKeyParams )
DECLARE_PEM_rw( GostKeyParams, GostKeyParams )
