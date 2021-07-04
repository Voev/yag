#pragma once

#define FUNC_PTR(x) ((void (*)(void))(x))

BUF_MEM* GsCreateBuffer(unsigned char* data, size_t size, unsigned long flags)
{
    BUF_MEM* buffer = BUF_MEM_new_ex(flags);
    if (NULL != buffer)
    {
        if (0 < BUF_MEM_grow(buffer, size))
        {
            BUF_MEM_free(buffer);
            buffer = NULL;
        }
        if (NULL != buffer && NULL != data)
        {
            memcpy(buffer->data, data, buffer->length);
        }
    }
    return buffer;
}

void GsDestroyBuffer(BUF_MEM* buffer)
{
    BUF_MEM_free(buffer);
}