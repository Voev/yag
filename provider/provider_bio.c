#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <gostone/provider_ctx.h>

static OSSL_FUNC_BIO_new_file_fn*    CoreBioNewFile   = NULL;
static OSSL_FUNC_BIO_new_membuf_fn*  CoreBioNewMembuf = NULL;
static OSSL_FUNC_BIO_read_ex_fn *    CoreBioReadEx    = NULL;
static OSSL_FUNC_BIO_write_ex_fn*    CoreBioWriteEx   = NULL;
static OSSL_FUNC_BIO_gets_fn*        CoreBioGets      = NULL;
static OSSL_FUNC_BIO_puts_fn*        CoreBioPuts      = NULL;
static OSSL_FUNC_BIO_ctrl_fn*        CoreBioCtrl      = NULL;
static OSSL_FUNC_BIO_free_fn*        CoreBioFree      = NULL;
static OSSL_FUNC_BIO_vprintf_fn*     CoreBioVprintf   = NULL;

int GsProvBioFromDispatch( const OSSL_DISPATCH* funcs )
{
    for( ; funcs->function_id != 0; ++funcs ) 
    {
        switch( funcs->function_id )
        {
        case OSSL_FUNC_BIO_NEW_FILE:
            if( !CoreBioNewFile )
            {
                CoreBioNewFile = OSSL_FUNC_BIO_new_file( funcs );
            }
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            if( !CoreBioNewMembuf )
            {
                CoreBioNewMembuf = OSSL_FUNC_BIO_new_membuf( funcs );
            }
            break;
        case OSSL_FUNC_BIO_READ_EX:
            if( !CoreBioReadEx )
            {
                CoreBioReadEx = OSSL_FUNC_BIO_read_ex( funcs );
            }
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            if( !CoreBioWriteEx )
            {
                CoreBioWriteEx = OSSL_FUNC_BIO_write_ex( funcs );
            }
            break;
        case OSSL_FUNC_BIO_GETS:
            if( !CoreBioGets )
            {
                CoreBioGets = OSSL_FUNC_BIO_gets( funcs );
            }
            break;
        case OSSL_FUNC_BIO_PUTS:
            if( !CoreBioPuts )
            {
                CoreBioPuts = OSSL_FUNC_BIO_puts( funcs );
            }
            break;
        case OSSL_FUNC_BIO_CTRL:
            if( !CoreBioCtrl )
            {
                CoreBioCtrl = OSSL_FUNC_BIO_ctrl( funcs );
            }
            break;
        case OSSL_FUNC_BIO_FREE:
            if( !CoreBioFree )
            {
                CoreBioFree = OSSL_FUNC_BIO_free( funcs );
            }
            break;
        case OSSL_FUNC_BIO_VPRINTF:
            if( !CoreBioVprintf )
            {
                CoreBioVprintf = OSSL_FUNC_BIO_vprintf( funcs );
            }
            break;
        }
    }
    return 1;
}

OSSL_CORE_BIO* GsProvBioNewFile(const char* filename, const char* mode)
{
    if (CoreBioNewFile)
    {
        return CoreBioNewFile(filename, mode);
    }
    return NULL;
}

OSSL_CORE_BIO* GsProvBioNewMembuf(const char* filename, int len)
{
    if (CoreBioNewMembuf)
    {
        return CoreBioNewMembuf(filename, len);
    }
    return NULL;
}

int GsProvBioReadEx(BIO* bio, char* data, size_t dataLen,
                    size_t* bytesRead)
{
    if (CoreBioReadEx)
    {
        return CoreBioReadEx(BIO_get_data(bio), data, dataLen, 
                             bytesRead);
    }
    return 0;
}

int GsProvBioWriteEx(BIO* bio, const char* data, size_t dataLen,
                     size_t* written)
{
    if (CoreBioWriteEx)
    {
        return CoreBioWriteEx(BIO_get_data(bio), data, dataLen,
                              written);
    }
    return 0;
}

int GsProvBioGets(BIO* bio, char* buf, int size)
{
    if (CoreBioGets)
    {
        return CoreBioGets(BIO_get_data(bio), buf, size);
    }
    return -1;
}

int GsProvBioPuts(BIO* bio, const char* str)
{
    if (CoreBioPuts)
    {
        return CoreBioPuts(BIO_get_data(bio), str);
    }
    return -1;
}

long GsProvBioCtrl(BIO* bio, int cmd, long num, void* ptr)
{
    if (CoreBioCtrl)
    {
        return CoreBioCtrl(BIO_get_data(bio), cmd, num, ptr);
    }
    return -1;
}

int GsProvBioVprintf(BIO* bio, const char* format, va_list ap)
{
    if (CoreBioVprintf)
    {
        return CoreBioVprintf(BIO_get_data(bio), format, ap);
    }
    return -1;
}

static int GsProvBioNew(BIO* bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

static int GsProvBioFree(BIO* bio)
{
    BIO_set_init(bio, 0);
    return 1;
}

BIO_METHOD* GsProvBioInitBioMethod(void)
{
    BIO_METHOD* coreBioMeth = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, 
                                           "BIO to Core filter");
    if (!coreBioMeth || 
        !BIO_meth_set_write_ex(coreBioMeth, GsProvBioWriteEx) || 
        !BIO_meth_set_read_ex(coreBioMeth, GsProvBioReadEx) || 
        !BIO_meth_set_puts(coreBioMeth, GsProvBioPuts) || 
        !BIO_meth_set_gets(coreBioMeth, GsProvBioGets) || 
        !BIO_meth_set_ctrl(coreBioMeth, GsProvBioCtrl) || 
        !BIO_meth_set_create(coreBioMeth, GsProvBioNew) || 
        !BIO_meth_set_destroy(coreBioMeth, GsProvBioFree)) 
    {
        BIO_meth_free(coreBioMeth);
        return NULL;
    }
    return coreBioMeth;
}

BIO* GsProvBioNewFromCoreBio(GsProvCtx* provCtx, OSSL_CORE_BIO* coreBio)
{
    BIO* outBio = NULL;
    const BIO_METHOD* coreBioMeth = GsProvCtxGet0CoreBioMeth(provCtx);
    if (coreBioMeth)
    {
        outBio = BIO_new(coreBioMeth);
        if (outBio)
            BIO_set_data(outBio, coreBio);
    }
    return outBio;
}
