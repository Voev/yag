#include <openssl/core_dispatch.h>
#include <gostone/common.h>
#include <gostone/implementations.h>
#include <gostone/decode/decode_impl.h>

#define DEFINE_DECODER_FUNCTIONS(name, structure, output)                      \
    const OSSL_DISPATCH DECODER_FUNCTIONS(name, structure, output)[] = {       \
        {OSSL_FUNC_DECODER_NEWCTX, FUNC_PTR(GsDecoderNewCtx)},                 \
        {OSSL_FUNC_DECODER_FREECTX, FUNC_PTR(GsDecoderFreeCtx)},               \
        {OSSL_FUNC_DECODER_DOES_SELECTION,                                     \
         FUNC_PTR(GsDecoderDoes##structure##Selection)},                       \
        {OSSL_FUNC_DECODER_DECODE,                                             \
         FUNC_PTR(GsDecoderDecode##structure##From##output)},                  \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, FUNC_PTR(GsDecoderExportObject)},    \
        {0, NULL}};

DEFINE_DECODER_FUNCTIONS(GostR3410_2012_256, PrivateKeyInfo, Der)
// DEFINE_DECODER_FUNCTIONS(GostR3410_2012_256, SubjectPublicKeyInfo, Der)
DEFINE_DECODER_FUNCTIONS(GostR3410_2012_256, TypeSpecific, Der)
