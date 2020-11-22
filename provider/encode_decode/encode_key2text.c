/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <ctype.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include "internal/ffc.h"
#include "crypto/bn.h"           /* bn_get_words() */
#include "crypto/dh.h"           /* dh_get0_params() */
#include "crypto/dsa.h"          /* dsa_get0_params() */
#include "crypto/ec.h"           /* ec_key_get_libctx */
#include "crypto/ecx.h"          /* ECX_KEY, etc... */
#include "crypto/rsa.h"          /* RSA_PSS_PARAMS_30, etc... */
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "endecoder_local.h"

DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_FMTu "%lu"
#  define BN_FMTx "%lx"
# endif

# ifdef SIXTY_FOUR_BIT
#  define BN_FMTu "%llu"
#  define BN_FMTx "%llx"
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_FMTu "%u"
#  define BN_FMTx "%x"
# endif


static OSSL_FUNC_encoder_newctx_fn GsTextEncoderNewCtx;
static OSSL_FUNC_encoder_freectx_fn GsTextEncoderNewCtx;

static OSSL_FUNC_encoder_get_params_fn GsTextEncoderGetParams;
static OSSL_FUNC_encoder_gettable_params_fn GsTextEncoderGettableParams;

static OSSL_FUNC_encoder_set_ctx_params_fn GsTextEncoderSetCtxParams;
static OSSL_FUNC_encoder_settable_ctx_params_fn GsTextEncoderSettableCtxParams;

static OSSL_FUNC_encoder_import_object_fn GsTextEncoderImportObject;
static OSSL_FUNC_encoder_free_object_fn GsTextEncoderFreeObject;
static OSSL_FUNC_encoder_encode_fn GsTextEncoderEncode;

static int ec_param_explicit_curve_to_text(BIO *out, const EC_GROUP *group,
                                           BN_CTX *ctx)
{
    const char *plabel = "Prime:";
    BIGNUM *p = NULL, *a = NULL, *b = NULL;

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (b == NULL
        || !EC_GROUP_get_curve(group, p, a, b, ctx))
        return 0;

    if (EC_GROUP_get_field_type(group) == NID_X9_62_characteristic_two_field) {
        int basis_type = EC_GROUP_get_basis_type(group);

        /* print the 'short name' of the base type OID */
        if (basis_type == NID_undef
            || BIO_printf(out, "Basis Type: %s\n", OBJ_nid2sn(basis_type)) <= 0)
            return 0;
        plabel = "Polynomial:";
    }
    return print_labeled_bignum(out, plabel, p)
        && print_labeled_bignum(out, "A:   ", a)
        && print_labeled_bignum(out, "B:   ", b);
}

static int ec_param_explicit_gen_to_text(BIO *out, const EC_GROUP *group,
                                         BN_CTX *ctx)
{
    const EC_POINT *point = NULL;
    BIGNUM *gen = NULL;
    const char *glabel = NULL;
    point_conversion_form_t form;

    form = EC_GROUP_get_point_conversion_form(group);
    point = EC_GROUP_get0_generator(group);
    gen = BN_CTX_get(ctx);

    if (gen == NULL
        || point == NULL
        || EC_POINT_point2bn(group, point, form, gen, ctx) == NULL)
        return 0;

    switch (form) {
    case POINT_CONVERSION_COMPRESSED:
       glabel = "Generator (compressed):";
       break;
    case POINT_CONVERSION_UNCOMPRESSED:
        glabel = "Generator (uncompressed):";
        break;
    case POINT_CONVERSION_HYBRID:
        glabel = "Generator (hybrid):";
        break;
    default:
        return 0;
    }
    return print_labeled_bignum(out, glabel, gen);
}

/* Print explicit parameters */
static int ec_param_explicit_to_text(BIO *out, const EC_GROUP *group,
                                     OSSL_LIB_CTX *libctx)
{
    int ret = 0, tmp_nid;
    BN_CTX *ctx = NULL;
    const BIGNUM *order = NULL, *cofactor = NULL;
    const unsigned char *seed;
    size_t seed_len = 0;

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);

    tmp_nid = EC_GROUP_get_field_type(group);
    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;

    seed = EC_GROUP_get0_seed(group);
    if (seed != NULL)
        seed_len = EC_GROUP_get_seed_len(group);
    cofactor = EC_GROUP_get0_cofactor(group);

    /* print the 'short name' of the field type */
    if (BIO_printf(out, "Field Type: %s\n", OBJ_nid2sn(tmp_nid)) <= 0
        || !ec_param_explicit_curve_to_text(out, group, ctx)
        || !ec_param_explicit_gen_to_text(out, group, ctx)
        || !print_labeled_bignum(out, "Order: ", order)
        || (cofactor != NULL
            && !print_labeled_bignum(out, "Cofactor: ", cofactor))
        || (seed != NULL
            && !print_labeled_buf(out, "Seed:", seed, seed_len)))
        goto err;
    ret = 1;
err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static int ec_param_to_text(BIO *out, const EC_GROUP *group,
                            OSSL_LIB_CTX *libctx)
{
    if (EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE) {
        const char *curve_name;
        int curve_nid = EC_GROUP_get_curve_name(group);

        /* Explicit parameters */
        if (curve_nid == NID_undef)
            return 0;

        if (BIO_printf(out, "%s: %s\n", "ASN1 OID", OBJ_nid2sn(curve_nid)) <= 0)
            return 0;

        curve_name = EC_curve_nid2nist(curve_nid);
        return (curve_name == NULL
                || BIO_printf(out, "%s: %s\n", "NIST CURVE", curve_name) > 0);
    } else {
        return ec_param_explicit_to_text(out, group, libctx);
    }
}

static int ec_to_text(BIO *out, const void *key, int selection)
{
    const EC_KEY *ec = key;
    const char *type_label = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t priv_len = 0, pub_len = 0;
    const EC_GROUP *group;
    int ret = 0;

    if (out == NULL || ec == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((group = EC_KEY_get0_group(ec)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_label = "Private-Key";
    else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_label = "Public-Key";
    else if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_label = "EC-Parameters";

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        const BIGNUM *priv_key = EC_KEY_get0_private_key(ec);

        if (priv_key == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto err;
        }
        priv_len = EC_KEY_priv2buf(ec, &priv);
        if (priv_len == 0)
            goto err;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        const EC_POINT *pub_pt = EC_KEY_get0_public_key(ec);

        if (pub_pt == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            goto err;
        }

        pub_len = EC_KEY_key2buf(ec, EC_KEY_get_conv_form(ec), &pub, NULL);
        if (pub_len == 0)
            goto err;
    }

    if (BIO_printf(out, "%s: (%d bit)\n", type_label,
                   EC_GROUP_order_bits(group)) <= 0)
        goto err;
    if (priv != NULL
        && !print_labeled_buf(out, "priv:", priv, priv_len))
        goto err;
    if (pub != NULL
        && !print_labeled_buf(out, "pub:", pub, pub_len))
        goto err;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ret = ec_param_to_text(out, group, ec_key_get_libctx(ec));
err:
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pub);
    return ret;
}

static void *key2text_newctx(void *provctx)
{
    return provctx;
}

static void key2text_freectx(ossl_unused void *vctx)
{
}

static const OSSL_PARAM *key2text_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int key2text_get_params(OSSL_PARAM params[], const char *input_type)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, input_type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEXT"))
        return 0;

    return 1;
}

static int key2text_encode(void *vctx, const void *key, int selection,
                           OSSL_CORE_BIO *cout,
                           int (*key2text)(BIO *out, const void *key,
                                           int selection),
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(vctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = key2text(out, key, selection);
    BIO_free(out);

    return ret;
}



static int GsTextEncoder2text_get_params(OSSL_PARAM params[])              \
    {                                                                   \
        return key2text_get_params(params, GsTextEncoder_input_type);          \
    }                                                                   \
    static void *GsTextEncoder2text_import_object(void *ctx, int selection,    \
                                           const OSSL_PARAM params[])   \
    {                                                                   \
        return ossl_prov_import_key(ossl_##GsTextEncoder_keymgmt_functions,    \
                                    ctx, selection, params);            \
    }                                                                   \
    static void GsTextEncoder2text_free_object(void *key)                      \
    {                                                                   \
        ossl_prov_free_key(ossl_##GsTextEncoder_keymgmt_functions, key);       \
    }                                                                   \
    static int GsTextEncoder2text_encode(void *vctx, OSSL_CORE_BIO *cout,      \
                                  const void *key,                      \
                                  const OSSL_PARAM key_abstract[],      \
                                  int selection,                        \
                                  OSSL_PASSPHRASE_CALLBACK *cb,         \
                                  void *cbarg)                          \
    {                                                                   \
        /* We don't deal with abstract objects */                       \
        if (key_abstract != NULL) {                                     \
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);     \
            return 0;                                                   \
        }                                                               \
        return key2text_encode(vctx, key, selection, cout,              \
                               type##_to_text, cb, cbarg);              \
    }                                                                   \
    const OSSL_DISPATCH ossl_##GsTextEncoder_to_text_encoder_functions[] = {   \
        { OSSL_FUNC_ENCODER_NEWCTX,                                     \
          (void (*)(void))key2text_newctx },                            \
        { OSSL_FUNC_ENCODER_FREECTX,                                    \
          (void (*)(void))key2text_freectx },                           \
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                            \
          (void (*)(void))key2text_gettable_params },                   \
        { OSSL_FUNC_ENCODER_GET_PARAMS,                                 \
          (void (*)(void))GsTextEncoder2text_get_params },                     \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                              \
          (void (*)(void))GsTextEncoder2text_import_object },                  \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                \
          (void (*)(void))GsTextEncoder2text_free_object },                    \
        { OSSL_FUNC_ENCODER_ENCODE,                                     \
          (void (*)(void))GsTextEncoder2text_encode },                         \
        { 0, NULL }                                                     \
    }

MAKE_TEXT_ENCODER(ec, ec);
