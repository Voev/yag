#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/pkcs12.h>

#include <gostone/common.h>
#include <gostone/provider_ctx.h>
#include <gostone/asn1/asn1.h>
#include <gostone/keymgmt/keymgmt_akey.h>
#include <gostone/encode/encode_impl.h>
#include <gostone/encode/encode_common.h>
#include <gostone/encode/encode_params.h>

static int GsEncodeKeyParamsToDerBio(BIO* out, const void* keyData,
                                     ossl_unused GsEncoderCtx* ctx,
                                     ossl_unused OSSL_PASSPHRASE_CALLBACK* cb,
                                     ossl_unused void* cbArg)
{
    return GsEncodeKeyParamsToDerBioImpl(out, keyData);
}

static int GsEncodeKeyParamsToPemBio(BIO* out, const void* keyData,
                                     ossl_unused GsEncoderCtx* ctx,
                                     ossl_unused OSSL_PASSPHRASE_CALLBACK* cb,
                                     ossl_unused void* cbArg)
{
    return GsEncodeKeyParamsToPemBioImpl(out, keyData);
}

int GsEncoderDoesTypeSpecificSelection(ossl_unused void* ctx, int selection)
{
    return GsEncoderCheckSelection(selection,
                                   OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
}

int GsEncoderEncodeTypeSpecificToDer(void* ctx, OSSL_CORE_BIO* cout,
                                     const void* keyData,
                                     const OSSL_PARAM keyAbstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg)
{
    return GsEncoderEncode(ctx, cout, keyData, keyAbstract, selection,
                           OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, cb, cbArg,
                           GsEncodeKeyParamsToDerBio);
}

int GsEncoderEncodeTypeSpecificToPem(void* ctx, OSSL_CORE_BIO* cout,
                                     const void* keyData,
                                     const OSSL_PARAM keyAbstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK* cb, void* cbArg)
{
    return GsEncoderEncode(ctx, cout, keyData, keyAbstract, selection,
                           OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, cb, cbArg,
                           GsEncodeKeyParamsToPemBio);
}
