#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

#include <gostone/provider_ctx.h>

struct gs_key_encoder_ctx_st
{
    GsProvCtx* provCtx;
    EVP_CIPHER* cipher;
};

typedef struct gs_key_encoder_ctx_st GsKeyEncoderCtx;

static OSSL_FUNC_encoder_newctx_fn GsKeyEncoderNewCtx;
static OSSL_FUNC_encoder_freectx_fn GsKeyEncoderFreeCtx;

static OSSL_FUNC_encoder_get_params_fn GsKeyEncoderGetParams;
static OSSL_FUNC_encoder_gettable_params_fn GsKeyEncoderGettableParams;

static OSSL_FUNC_encoder_set_ctx_params_fn GsKeyEncoderSetCtxParams;
static OSSL_FUNC_encoder_settable_ctx_params_fn GsKeyEncoderSettableCtxParams;

static OSSL_FUNC_encoder_import_object_fn GsKeyEncoderImportObject;
static OSSL_FUNC_encoder_free_object_fn GsKeyEncoderFreeObject;
static OSSL_FUNC_encoder_encode_fn GsKeyEncoderEncode;


OSSL_DISPATCH gDerEncoderFunctions[] =
{
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))GsKeyEncoderNewCtx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))GsKeyEncoderFreeCtx },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))GsKeyEncoderGettableParams },
    { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))GsKeyEncoderGetParams },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))GsKeyEncoderSettableCtxParams },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))GsKeyEncoderSetCtxParams },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))GsKeyEncoderImportObject },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))GsKeyEncoderImportObject },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))GsKeyEncoderEncode },
    { 0, NULL }
};

void* GsKeyEncoderNewCtx( void* provCtx )
{
    GsKeyEncoderCtx* ctx = OPENSSL_zalloc( sizeof( *ctx ) );
    if( ctx )
    {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

void GsKeyEncoderFreeCtx( void* vctx )
{
    GsKeyEncoderCtx* ctx = ( GsKeyEncoderCtx* )vctx;
    if( ctx )
    {
        EVP_CIPHER_free( ctx->cipher );
        OPENSSL_free( ctx );
    }
}

const OSSL_PARAM* GsKeyEncoderGettableParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gGettablesParam[] =
    {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };
    return gGettablesParam;
}

int GsKeyEncoderGetparams( OSSL_PARAM params[],
                           const char* inputType,
                           const char* outputType )
{
    OSSL_PARAM* p = OSSL_PARAM_locate( params, OSSL_ENCODER_PARAM_INPUT_TYPE );
    if( p && !OSSL_PARAM_set_utf8_ptr( p, inputType ) )
    {
        return 0;
    }
    p = OSSL_PARAM_locate( params, OSSL_ENCODER_PARAM_OUTPUT_TYPE );
    if( p && !OSSL_PARAM_set_utf8_ptr( p, outputType ) )
    {
        return 0;
    }
    return 1;
}

const OSSL_PARAM* GsKeyEncoderSettableCtxParams( ossl_unused void* provCtx )
{
    static const OSSL_PARAM gSettableCtxParams[] =
    {
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_CIPHER,     NULL, 0 ),
        OSSL_PARAM_utf8_string( OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0 ),
        OSSL_PARAM_END,
    };
    return gSettableCtxParams;
}

int GsKeyEncoderSetCtxParams( void* vctx, const OSSL_PARAM params[] )
{
    GsKeyEncoderCtx* ctx = ( GsKeyEncoderCtx* )vctx;
    OSSL_LIB_CTX* libCtx = GsProvCtxGet0LibCtx( ctx->provCtx );
    const OSSL_PARAM* cipherParam =
        OSSL_PARAM_locate_const( params, OSSL_ENCODER_PARAM_CIPHER );

    if( cipherParam )
    {
        const OSSL_PARAM* propsParam;

        propsParam = OSSL_PARAM_locate_const( params, OSSL_ENCODER_PARAM_PROPERTIES );

        const char* cipherName = NULL;
        const char* props = NULL;

        if( !OSSL_PARAM_get_utf8_string_ptr( cipherParam, &cipherName ) )
        {
            return 0;
        }
        if( props && !OSSL_PARAM_get_utf8_string_ptr( propsParam, &props ) )
        {
            return 0;
        }

        EVP_CIPHER_free( ctx->cipher );
        if( cipherName )
        {
            ctx->cipher = EVP_CIPHER_fetch( libCtx, cipherName, props );
        }
        return 0;
    }
    return 1;
}

void* GsKeyEncoderCtxImportObject( void* vctx, int selection, const OSSL_PARAM params[] )
{
    return NULL;
}

void GsKeyEncoderFreeObject( void* key )
{
}

static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,
                                          void *params, int params_type,
                                          i2d_of_void *k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final PKCS#8 info */
    PKCS8_PRIV_KEY_INFO *p8info = NULL;


    if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
                            params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        p8info = NULL;
    }

    return p8info;
}

static X509_SIG *key_to_encp8(const void *key, int key_nid,
                              void *params, int params_type,
                              i2d_of_void *k2d, struct key2any_ctx_st *ctx)
{
    PKCS8_PRIV_KEY_INFO *p8info =
        key_to_p8info(key, key_nid, params, params_type, k2d);

    X509_SIG *p8 = NULL;
    char kstr[PEM_BUFSIZE];
    size_t klen = 0;

    if (ctx->cipher == NULL)
        return NULL;

    if (!ossl_pw_get_passphrase(kstr, sizeof(kstr), &klen, NULL, 1,
                                &ctx->pwdata)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
        return NULL;
    }
    /* First argument == -1 means "standard" */
    p8 = PKCS8_encrypt(-1, ctx->cipher, kstr, klen, NULL, 0, 0, p8info);
    OPENSSL_cleanse(kstr, klen);

    PKCS8_PRIV_KEY_INFO_free(p8info);
    return p8;
}

///////////////////////////////////////////////////
/// \brief key_to_der_pkcs8_bio
/// \param out
/// \param key
/// \param key_nid
/// \param p2s
/// \param k2d
/// \param ctx
/// \return
///
///
///
static int key_to_der_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = i2d_PKCS8_bio(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static int key_to_pem_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = PEM_write_bio_PKCS8(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}


static int
GsKey2AnyEncode( struct key2any_ctx_st *ctx, OSSL_CORE_BIO *cout,
                 const void *key, int type,
                 key_to_der_fn *writer,
                 OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg,
                 key_to_paramstring_fn *key2paramstring,
                          i2d_of_void *key2der)
{
    int ret = 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    } else
    {
        BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

        if (out != NULL
            && writer != NULL
            && ossl_pw_set_ossl_passphrase_cb(&ctx->pwdata, cb, cbarg))
            ret = writer(out, key, type, key2paramstring, key2der, ctx);

        BIO_free(out);
    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }
    return ret;
}

int GsKeyEncoderEncode( void* ctx, OSSL_CORE_BIO* cout,
                        const void *key, const OSSL_PARAM key_abstract[],
                        int selection,
                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    if (key_abstract != NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
    {
        return key2any_encode(ctx, cout, key, ec_evp_type,
                              type##_check_key_type,                    \
                              key_to_der_pkcs8_bio,              \
                              cb, cbarg,                                \
                              prepare_##type##_params,                  \
                              type##_priv_to_der);                      \
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)              \
        return key2any_encode(ctx, cout, key, ec_evp_type,          \
                              type##_check_key_type,                    \
                              key_to_der_pubkey_bio,             \
                              cb, cbarg,                                \
                              prepare_##type##_params,                  \
                              type##_pub_to_der);                       \
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)          \
        return key2any_encode_params(ctx, cout, key,                    \
                                     ec_evp_type,                   \
                                     type##_check_key_type,             \
                                     type##_params_to_der_bio);  \
                                                                        \
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);             \
    return 0;                                                           \
}                                                                       \


typedef int check_key_type_fn(const void *key, int nid);
typedef int key_to_paramstring_fn(const void *key, int nid,
                                  void **str, int *strtype);
typedef int key_to_der_fn(BIO *out, const void *key, int key_nid,
                          key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                          struct key2any_ctx_st *ctx);
typedef int write_bio_of_void_fn(BIO *bp, const void *x);

static X509_PUBKEY *key_to_pubkey(const void *key, int key_nid,
                                  void *params, int params_type,
                                  i2d_of_void k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final X509_PUBKEY */
    X509_PUBKEY *xpk = NULL;


    if ((xpk = X509_PUBKEY_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid),
                                   params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        xpk = NULL;
    }

    return xpk;
}

static int key_to_der_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = i2d_PKCS8_bio(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static int key_to_pem_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = PEM_write_bio_PKCS8(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static int key_to_der_pubkey_bio(BIO *out, const void *key, int key_nid,
                                 key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                 struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    xpk = key_to_pubkey(key, key_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = i2d_X509_PUBKEY_bio(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}

static int key_to_pem_pubkey_bio(BIO *out, const void *key, int key_nid,
                                 key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                 struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    xpk = key_to_pubkey(key, key_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = PEM_write_bio_X509_PUBKEY(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}

#define der_output_type         "DER"
#define pem_output_type         "PEM"

static int prepare_ec_explicit_params(const void *eckey,
                                      void **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    params->length = i2d_ECParameters(eckey, &params->data);
    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }

    *pstrtype = V_ASN1_SEQUENCE;
    *pstr = params;
    return 1;
}

static int prepare_ec_params(const void *eckey, int nid,
                             void **pstr, int *pstrtype)
{
    int curve_nid;
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    ASN1_OBJECT *params = NULL;

    if (group == NULL)
        return 0;
    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        params = OBJ_nid2obj(curve_nid);
        if (params == NULL)
            return 0;
    }

    if (curve_nid != NID_undef
        && (EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE)) {
        if (OBJ_length(params) == 0) {
            /* Some curves might not have an associated OID */
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_OID);
            ASN1_OBJECT_free(params);
            return 0;
        }
        *pstr = params;
        *pstrtype = V_ASN1_OBJECT;
        return 1;
    } else {
        return prepare_ec_explicit_params(eckey, pstr, pstrtype);
    }
}

static int ec_params_to_der_bio(BIO *out, const void *eckey)
{
    return i2d_ECPKParameters_bio(out, EC_KEY_get0_group(eckey));
}

static int ec_params_to_pem_bio(BIO *out, const void *eckey)
{
    return PEM_write_bio_ECPKParameters(out, EC_KEY_get0_group(eckey));
}

static int ec_pub_to_der(const void *eckey, unsigned char **pder)
{
    return i2o_ECPublicKey(eckey, pder);
}

static int ec_priv_to_der(const void *veckey, unsigned char **pder)
{
    EC_KEY *eckey = (EC_KEY *)veckey;
    unsigned int old_flags;
    int ret = 0;

    /*
     * For PKCS8 the curve name appears in the PKCS8_PRIV_KEY_INFO object
     * as the pkeyalg->parameter field. (For a named curve this is an OID)
     * The pkey field is an octet string that holds the encoded
     * ECPrivateKey SEQUENCE with the optional parameters field omitted.
     * We omit this by setting the EC_PKEY_NO_PARAMETERS flag.
     */
    old_flags = EC_KEY_get_enc_flags(eckey); /* save old flags */
    EC_KEY_set_enc_flags(eckey, old_flags | EC_PKEY_NO_PARAMETERS);
    ret = i2d_ECPrivateKey(eckey, pder);
    EC_KEY_set_enc_flags(eckey, old_flags); /* restore old flags */
    return ret; /* return the length of the der encoded data */
}


static int key2any_encode_params(struct key2any_ctx_st *ctx,
                                 OSSL_CORE_BIO *cout,
                                 const void *key, int type,
                                 check_key_type_fn *checker,
                                 write_bio_of_void_fn *writer)
{
    int ret = 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    } else if (checker == NULL || checker(key, type)) {
        BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

        if (out != NULL && writer != NULL)
            ret = writer(out, key);

        BIO_free(out);
    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }

    return ret;
}

#define MAKE_ENCODER(impl, type, evp_type, output)                          \
    static OSSL_FUNC_encoder_get_params_fn                                  \
    ec2der_get_params;                                           \
    static OSSL_FUNC_encoder_import_object_fn                               \
    ec2der_import_object;                                        \
    static OSSL_FUNC_encoder_free_object_fn                                 \
    ec2der_free_object;                                          \
    static OSSL_FUNC_encoder_encode_fn ec2der_encode;            \
                                                                            \
    static int ec2der_get_params(OSSL_PARAM params[])            \
    {                                                                       \
        return key2any_get_params(params, ec_input_type,                \
                                  output##_output_type);                    \
    }                                                                       \
    static void *                                                           \
    ec2der_import_object(void *vctx, int selection,              \
                                    const OSSL_PARAM params[])              \
    {                                                                       \
        struct key2any_ctx_st *ctx = vctx;                                  \
        return ossl_prov_import_key(ossl_ec_keymgmt_functions,        \
                                    ctx->provctx, selection, params);       \
    }                                                                       \
    static void ec2der_free_object(void *key)                    \
    {                                                                       \
        ossl_prov_free_key(ossl_ec_keymgmt_functions, key);           \
    }                                                                       \
    static int                                                              \
    ec2der_encode(void *ctx, OSSL_CORE_BIO *cout,                \
                             const void *key,                               \
                             const OSSL_PARAM key_abstract[],               \
                             int selection,                                 \
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)     \
    {                                                                       \
        /* We don't deal with abstract objects */                           \
        if (key_abstract != NULL) {                                         \
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);         \
            return 0;                                                       \
        }                                                                   \
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)             \
            return key2any_encode(ctx, cout, key, ec_evp_type,          \
                                  type##_check_key_type,                    \
                                  key_to_der_pkcs8_bio,              \
                                  cb, cbarg,                                \
                                  prepare_##type##_params,                  \
                                  type##_priv_to_der);                      \
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)              \
            return key2any_encode(ctx, cout, key, ec_evp_type,          \
                                  type##_check_key_type,                    \
                                  key_to_der_pubkey_bio,             \
                                  cb, cbarg,                                \
                                  prepare_##type##_params,                  \
                                  type##_pub_to_der);                       \
        if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)          \
            return key2any_encode_params(ctx, cout, key,                    \
                                         ec_evp_type,                   \
                                         type##_check_key_type,             \
                                         type##_params_to_der_bio);  \
                                                                            \
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);             \
        return 0;                                                           \
    }                                                                       \
    const OSSL_DISPATCH ossl_ec_to_der_encoder_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX,                                         \
          (void (*)(void))key2any_newctx },                                 \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
          (void (*)(void))key2any_freectx },                                \
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                                \
          (void (*)(void))key2any_gettable_params },                        \
        { OSSL_FUNC_ENCODER_GET_PARAMS,                                     \
          (void (*)(void))ec2der_get_params },                   \
        { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
          (void (*)(void))key2any_settable_ctx_params },                    \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
          (void (*)(void))key2any_set_ctx_params },                         \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
          (void (*)(void))ec2der_import_object },                \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
          (void (*)(void))ec2der_free_object },                  \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
          (void (*)(void))ec2der_encode },                       \
        { 0, NULL }                                                         \
    }

MAKE_ENCODER(ec, ec, EVP_PKEY_EC, der);
MAKE_ENCODER(ec, ec, EVP_PKEY_EC, pem);
