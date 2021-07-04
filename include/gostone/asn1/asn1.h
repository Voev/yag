#pragma once
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>

int GsEncodeKeyParamsToDerBioImpl(BIO* out, const void* keyData);
int GsEncodeKeyParamsToPemBioImpl(BIO* out, const void* keyData);
int GsPackKeyParams(const void* keyData, ASN1_STRING** params);
