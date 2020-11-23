#include <openssl/param_build.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>

#include <gostone/common.h>
#include <gostone/provider_ctx.h>
#include <gostone/implementations.h>
#include <gostone/keymgmt/keymgmt.h>

static void* GsKeyMgmtNew( void* provCtx );
static void GsKeyMgmtFree( void* keyData );
static void* GsKeyMgmtLoad( const void* reference, size_t referenceSize );
//static int GsKeyMgmtExport( void* keyData, int selection,
//                            OSSL_CALLBACK* paramCb, void* cbArg );
static int GsKeyMgmtExport( void* keyData, int selection, OSSL_CALLBACK* paramCb,
                            void* cbArg);
static const OSSL_PARAM* GsKeyMgmtExportTypes( int selection );

const OSSL_DISPATCH gGostR341012_256Funcs[] =
{
    { OSSL_FUNC_KEYMGMT_NEW, FUNC_PTR( GsKeyMgmtNew ) },
    { OSSL_FUNC_KEYMGMT_FREE, FUNC_PTR( GsKeyMgmtFree ) },
    { OSSL_FUNC_KEYMGMT_MATCH, FUNC_PTR( GsKeyMgmtMatch ) },
    { OSSL_FUNC_KEYMGMT_HAS, FUNC_PTR( GsKeyMgmtHas ) },
    { OSSL_FUNC_KEYMGMT_VALIDATE, FUNC_PTR( GsKeyMgmtValidate ) },
    { OSSL_FUNC_KEYMGMT_LOAD, FUNC_PTR( GsKeyMgmtLoad ) },
    //{ OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))GsKeyMgmtGetParams },
    //{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))GsKeyMgmtGettableParams },
    //{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))GsKeyMgmtimport },
    //{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))GsKeyMgmtimport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, FUNC_PTR( GsKeyMgmtExport ) },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, FUNC_PTR( GsKeyMgmtExportTypes ) },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, FUNC_PTR( GsKeyMgmtGenInit ) },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, FUNC_PTR( GsKeyMgmtGenSetTemplate ) },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, FUNC_PTR( GsKeyMgmtGenSetParams ) },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, FUNC_PTR( GsKeyMgmtGenSettableParams ) },
    { OSSL_FUNC_KEYMGMT_GEN, FUNC_PTR( GsKeyMgmtGen ) },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, FUNC_PTR( GsKeyMgmtGenCleanup ) },
    { 0, NULL }
};

const OSSL_DISPATCH gGostR341012_512Funcs[] =
{
    /*
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))GsKeyMgmtnewdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))GsKeyMgmtfreedata },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))GsKeyMgmtmatch },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))GsKeyMgmtvalidate },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))GsKeyMgmthas },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))GsKeyMgmtload },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))GsKeyMgmtget_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))GsKeyMgmtgettable_params },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))GsKeyMgmtimport },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))GsKeyMgmtimport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))GsKeyMgmtexport },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))GsKeyMgmtexport_types },

    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))GsKeyMgmtgen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))GsKeyMgmtgen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))GsKeyMgmtgen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))GsKeyMgmtgen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))GsKeyMgmtgen_cleanup },*/
    { 0, NULL }
};


void* GsKeyMgmtNew( void* provCtx )
{
    GsProvCtx* ctx = ( GsProvCtx* )provCtx;
    return EC_KEY_new_ex( GsProvCtxGet0LibCtx( ctx ), NULL );
}

static void GsKeyMgmtFree( void* keyData )
{
    EC_KEY_free( keyData );
}

void* GsKeyMgmtLoad( const void* reference, size_t referenceSize )
{
    EC_KEY* key = NULL;
    if( referenceSize == sizeof( key ) )
    {
        key = *( EC_KEY** )reference;
        *( EC_KEY** )reference = NULL;
        return key;
    }
    return NULL;
}


int ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                    OSSL_PARAM params[], 
                    BN_CTX *bnctx, unsigned char **genbuf)
{
    int ret = 0, curve_nid, encoding_flag;
    const char *field_type, *encoding_name;
    const BIGNUM *cofactor, *order;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    point_conversion_form_t genform;
    const EC_POINT *genpt;
    unsigned char *seed = NULL;
    size_t genbuf_len, seed_len;

    if (group == NULL) {
        return 0;
    }

    
    curve_nid = EC_GROUP_get_curve_name(group);
     {
        /* named curve */
        const char *curve_name = OBJ_nid2sn(curve_nid);

        if (curve_name == NULL
            || !OSSL_PARAM_BLD_push_utf8_ptr(tmpl, params,
                                             curve_name, strlen(curve_name)))
        {
            goto err;
        }
    }
    ret = 1;
err:
    return ret;
}


static ossl_inline
int key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private,
                  unsigned char **pub_key)
{
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_point = NULL;
    const EC_GROUP *ecg = NULL;
    size_t pub_key_len = 0;
    int ret = 0;
    BN_CTX *bnctx = NULL;

    if (eckey == NULL
        || (ecg = EC_KEY_get0_group(eckey)) == NULL)
        return 0;

    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    if (pub_point != NULL) {
        OSSL_PARAM *p = NULL, *px = NULL, *py = NULL;
        /*
         * EC_POINT_point2buf() can generate random numbers in some
         * implementations so we need to ensure we use the correct libctx.
         */
        bnctx = BN_CTX_new_ex(NULL);
        if (bnctx == NULL)
            goto err;

        if (p != NULL || tmpl != NULL) {
            /* convert pub_point to a octet string according to the SECG standard */
            if ((pub_key_len = EC_POINT_point2buf(ecg, pub_point,
                                                  POINT_CONVERSION_COMPRESSED,
                                                  pub_key, bnctx)) == 0)
                goto err;
        }
        if (px != NULL || py != NULL) {
            if (px != NULL)
                x = BN_CTX_get(bnctx);
            if (py != NULL)
                y = BN_CTX_get(bnctx);

            if (!EC_POINT_get_affine_coordinates(ecg, pub_point, x, y, bnctx))
                goto err;
            if (px != NULL
                && !OSSL_PARAM_BLD_push_BN(tmpl, px, x))
                goto err;
            if (py != NULL
                && !OSSL_PARAM_BLD_push_BN(tmpl, py, y))
                goto err;
        }
    }

    if (priv_key != NULL && include_private) {
        size_t sz;
        int ecbits;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
         *
         * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
         * to preallocate the BIGNUM internal buffer to a fixed public size big
         * enough that operations performed during the processing never trigger
         * a realloc which would leak the size of the scalar through memory
         * accesses.
         *
         * Fixed Length
         * ------------
         *
         * The order of the large prime subgroup of the curve is our choice for
         * a fixed public size, as that is generally the upper bound for
         * generating a private key in EC cryptosystems and should fit all valid
         * secret scalars.
         *
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of "words"
         * required for the internal representation of the order, and we
         * preallocate 2 extra "words" in case any of the subsequent processing
         * might temporarily overflow the order length.
         */
        ecbits = EC_GROUP_order_bits(ecg);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7 ) / 8;

        if (!OSSL_PARAM_BLD_push_BN(tmpl, params, priv_key))
            goto err;
    }
    ret = 1;
 err:
    BN_CTX_free(bnctx);
    return ret;
}

int GsKeyMgmtExport( void* keyData, int selection, OSSL_CALLBACK* paramCb, void* cbArg )
{
    EC_KEY* akey = ( EC_KEY* )keyData;
    OSSL_PARAM_BLD* tmpl = NULL;
    OSSL_PARAM* params = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* genbuf = NULL;
    BN_CTX *bnctx = NULL;
    int ok = 1;

    if( !akey )
    {
        return 0;
    }

    if( !( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) )
    {
        return 0;
    }
    if(  ( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) &&
        !( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY  ) )
    {
        return 0;
    }
    if(  ( selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) && 
        !( selection & OSSL_KEYMGMT_SELECT_KEYPAIR ) )
    {
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if( selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) 
    {
        bnctx = BN_CTX_new_ex(NULL);
        if (bnctx == NULL) {
            ok = 0;
            goto end;
        }
        BN_CTX_start(bnctx);
        ok = ok && ec_group_todata(EC_KEY_get0_group(akey), tmpl, NULL,
                                   bnctx, &genbuf);
    }

    if( selection & OSSL_KEYMGMT_SELECT_KEYPAIR ) 
    {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && key_to_params( akey, tmpl, NULL, include_private, &pub_key);
    }
    if( selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS )
    {
        //ok = ok && otherparams_to_params( akey, tmpl, NULL);
    }
    if( ok && (params = OSSL_PARAM_BLD_to_param(tmpl) ) != NULL)
    {
        ok = paramCb( params, cbArg );
    }
end:
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_free(pub_key);
    OPENSSL_free(genbuf);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ok;
}

const OSSL_PARAM* GsKeyMgmtExportTypes( int selection )
{
    return NULL;
}

