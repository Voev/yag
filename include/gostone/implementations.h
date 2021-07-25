#pragma once
#include <openssl/types.h>

extern const OSSL_DISPATCH gGostR341112_256Funcs[];
extern const OSSL_DISPATCH gGostR341112_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_256Funcs[];
extern const OSSL_DISPATCH gGostR341012_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_SignatureFunctions[];

#define STRUCTURE_TypeSpecific "type-specific"
#define STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"
#define STRUCTURE_PrivateKeyInfo "PrivateKeyInfo"
#define STRUCTURE_SubjectPublicKeyInfo "SubjectPublicKeyInfo"

#define ENCODER_FUNCTIONS(name, structure, output)                             \
    g##name##Of##structure##To##output##Funcs
#define ENCODER_FOR_STRUCTURE(name, structure, output)                         \
    {                                                                          \
        SN_id_##name,                                                          \
            "provider=gostone,output=" #output                                 \
            ",structure=" STRUCTURE_##structure,                               \
            ENCODER_FUNCTIONS(name, structure, output), LN_id_##name           \
    }

#define TEXT_ENCODER_FUNCTIONS(name) g##name##ToTextFuncs
#define TEXT_ENCODER(name)                                                     \
    {                                                                          \
        SN_id_##name, "provider=gostone,output=text",                          \
            TEXT_ENCODER_FUNCTIONS(name), LN_id_##name                         \
    }

#define DECLARE_ENCODER_FUNCTIONS(name, structure, output)                     \
    extern const OSSL_DISPATCH ENCODER_FUNCTIONS(name, structure, output)[];

#define DECLARE_TEXT_ENCODER_FUNCTIONS(name)                                   \
    extern const OSSL_DISPATCH TEXT_ENCODER_FUNCTIONS(name)[];

DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, PrivateKeyInfo, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, PrivateKeyInfo, Pem)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, SubjectPublicKeyInfo, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, SubjectPublicKeyInfo, Pem)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, TypeSpecific, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_256, TypeSpecific, Pem)
DECLARE_TEXT_ENCODER_FUNCTIONS(GostR3410_2012_256)

DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, PrivateKeyInfo, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, PrivateKeyInfo, Pem)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, SubjectPublicKeyInfo, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, SubjectPublicKeyInfo, Pem)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, TypeSpecific, Der)
DECLARE_ENCODER_FUNCTIONS(GostR3410_2012_512, TypeSpecific, Pem)
DECLARE_TEXT_ENCODER_FUNCTIONS(GostR3410_2012_512)

extern const OSSL_DISPATCH gKuznyechikECBFuncs[];
