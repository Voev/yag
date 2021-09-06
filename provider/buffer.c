#include <string.h>
#include <openssl/buffer.h>
#include <gostone/buffer.h>

size_t BUF_MEM_size(const BUF_MEM* buf)
{
    return buf ? buf->length : 0;
}

unsigned char* BUF_MEM_data(const BUF_MEM* buf)
{
    return buf ? (unsigned char*)buf->data : NULL;
}

unsigned char* BUF_MEM_shifted_data(const BUF_MEM* buf, size_t shift)
{
    return buf && buf->length > shift ? (unsigned char*)buf->data + shift
                                      : NULL;
}

int BUF_MEM_empty(const BUF_MEM* buf)
{
    return !(buf && buf->data != NULL && buf->length > 0);
}

int BUF_MEM_append(BUF_MEM* buf, const unsigned char* data, size_t size)
{
    size_t oldSize = BUF_MEM_size(buf);
    if (BUF_MEM_grow(buf, size) <= 0)
    {
        return 0;
    }
    memcpy(buf->data + oldSize, data, size);
    return 1;
}