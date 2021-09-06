#pragma once
#include <stddef.h>
#include <openssl/ossl_typ.h>

size_t BUF_MEM_size(const BUF_MEM* buf);

unsigned char* BUF_MEM_data(const BUF_MEM* buf);

unsigned char* BUF_MEM_shifted_data(const BUF_MEM* buf, size_t shift);

int BUF_MEM_empty(const BUF_MEM* buf);

int BUF_MEM_append(BUF_MEM* buf, const unsigned char* data, size_t size);