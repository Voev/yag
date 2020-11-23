#pragma once
#include <openssl/asn1.h>
#include <openssl/pem.h> 
#include <openssl/ossl_typ.h>

typedef struct
{
    ASN1_OCTET_STRING* wrappedKey;
    ASN1_OCTET_STRING* wrappedKeyMac;
}
GOST_KEY_INFO;
DECLARE_ASN1_FUNCTIONS( GOST_KEY_INFO )

typedef struct
{
    ASN1_OBJECT*        cipher;
    X509_PUBKEY*        ephemeralKey;
    ASN1_OCTET_STRING*  iv;
}
GOST_KEY_AGREEMENT_INFO;
DECLARE_ASN1_FUNCTIONS( GOST_KEY_AGREEMENT_INFO )

typedef struct
{
    GOST_KEY_INFO*           keyInfo;
    GOST_KEY_AGREEMENT_INFO* keyAgreeInfo;
}
GOST_KEY_TRANSPORT;
DECLARE_ASN1_FUNCTIONS( GOST_KEY_TRANSPORT )

typedef struct
{
    GOST_KEY_TRANSPORT* gkt;
}
GOST_CLIENT_KEY_EXCHANGE;
DECLARE_ASN1_FUNCTIONS( GOST_CLIENT_KEY_EXCHANGE )

typedef struct 
{
    ASN1_OCTET_STRING* psexp;
    X509_PUBKEY*       ephemeralKey;
}
PSKeyTransport_gost;
DECLARE_ASN1_FUNCTIONS( PSKeyTransport_gost )

typedef struct
{
    ASN1_OBJECT* keyParams;
    ASN1_OBJECT* hashParams;
    ASN1_OBJECT* cipherParams;
}
GostKeyParams;
DECLARE_ASN1_FUNCTIONS( GostKeyParams )
DECLARE_PEM_rw( GostKeyParams, GostKeyParams )

typedef struct
{
    ASN1_OCTET_STRING* iv;
    ASN1_OBJECT*       sbox;
}
GOST89_PARAMS;
DECLARE_ASN1_FUNCTIONS( GOST89_PARAMS )

typedef struct
{
    ASN1_OCTET_STRING* maskedPrivateKey;
    ASN1_OCTET_STRING* publicKey;
}
GOST_MASKED_KEY;
DECLARE_ASN1_FUNCTIONS( GOST_MASKED_KEY )
