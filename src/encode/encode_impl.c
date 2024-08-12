#include <openssl/core_dispatch.h>
#include <yag/common.h>
#include <yag/implementations.h>
#include <yag/encode/encode_impl.h>

#define DEFINE_ENCODER_FUNCTIONS(name, structure, output)                      \
    const OSSL_DISPATCH ENCODER_FUNCTIONS(name, structure, output)[] = {       \
        {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderNewCtx)},                 \
        {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderFreeCtx)},               \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, FUNC_PTR(GsEncoderSetCtxParams)},   \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                                \
         FUNC_PTR(GsEncoderSettableCtxParams)},                                \
        {OSSL_FUNC_ENCODER_DOES_SELECTION,                                     \
         FUNC_PTR(GsEncoderDoes##structure##Selection)},                       \
        {OSSL_FUNC_ENCODER_ENCODE,                                             \
         FUNC_PTR(GsEncoderEncode##structure##To##output)},                    \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},    \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},        \
        {0, NULL}};

#define DEFINE_TEXT_ENCODER_FUNCTIONS(name)                                    \
    const OSSL_DISPATCH TEXT_ENCODER_FUNCTIONS(name)[] = {                     \
        {OSSL_FUNC_ENCODER_NEWCTX, FUNC_PTR(GsEncoderToTextNewCtx)},           \
        {OSSL_FUNC_ENCODER_FREECTX, FUNC_PTR(GsEncoderToTextFreeCtx)},         \
        {OSSL_FUNC_ENCODER_ENCODE, FUNC_PTR(GsEncoderToTextEncode)},           \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, FUNC_PTR(GsEncoderImportObject)},    \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, FUNC_PTR(GsEncoderFreeObject)},        \
        {0, NULL}};

DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, PrivateKeyInfo, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, PrivateKeyInfo, Pem)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, SubjectPublicKeyInfo, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, SubjectPublicKeyInfo, Pem)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, TypeSpecific, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_256, TypeSpecific, Pem)
DEFINE_TEXT_ENCODER_FUNCTIONS(GostR3410_2012_256)

DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, PrivateKeyInfo, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, PrivateKeyInfo, Pem)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, SubjectPublicKeyInfo, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, SubjectPublicKeyInfo, Pem)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, TypeSpecific, Der)
DEFINE_ENCODER_FUNCTIONS(GostR3410_2012_512, TypeSpecific, Pem)
DEFINE_TEXT_ENCODER_FUNCTIONS(GostR3410_2012_512)