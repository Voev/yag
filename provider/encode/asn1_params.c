#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include "asn1_params.h"

ASN1_NDEF_SEQUENCE( GostKeyParams ) =
{
    ASN1_SIMPLE( GostKeyParams, keyParams, ASN1_OBJECT ),
    ASN1_OPT( GostKeyParams, hashParams, ASN1_OBJECT ),
    ASN1_OPT( GostKeyParams, cipherParams, ASN1_OBJECT ),
}
ASN1_NDEF_SEQUENCE_END( GostKeyParams )
IMPLEMENT_ASN1_FUNCTIONS( GostKeyParams )
IMPLEMENT_PEM_rw( GostKeyParams, GostKeyParams, "GOST KEY PARAMS", GostKeyParams )
