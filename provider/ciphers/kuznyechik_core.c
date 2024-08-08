#include <openssl/crypto.h>
#include <gostone/ciphers/kuznyechik_core.h>
#include <gostone/ciphers/kuznyechik_defs.h>

static inline int IsAligned(const void* ptr, size_t alignment)
{
    return !((uintptr_t)ptr % alignment);
}

static void SubstituteBytes(uint8_t* block, const uint8_t* sbox)
{
    OPENSSL_assert(block);
    OPENSSL_assert(sbox);

    for (size_t i = 0; i < BlockLengthInBytes; ++i)
    {
        block[i] = sbox[block[i]];
    }
}

static void DirectSubstituteBytes(uint8_t* block)
{
    SubstituteBytes(block, gDirectPi);
}

static void InverseSubstituteBytes(uint8_t* block)
{
    SubstituteBytes(block, gInversePi);
}

static inline uint8_t* GetAt(const uint8_t* table, size_t index)
{
    OPENSSL_assert(table);
    OPENSSL_assert(index < 0x1000);

    return (uint8_t*)(&table[index * BlockLengthInBytes]);
}

static inline void XorBlocks(uint8_t* dst, const uint8_t* src)
{
    OPENSSL_assert(dst);
    OPENSSL_assert(IsAligned(dst, 8));
    OPENSSL_assert(src);
    OPENSSL_assert(IsAligned(src, 8));

    const size_t size = BlockLengthInBytes / sizeof(uint64_t);

    for (size_t i = 0; i < size; ++i)
    {
        dst[i] ^= src[i];
    }

    return;
}

static inline void CopyBlock(uint8_t* dst, const uint8_t* src)
{
    OPENSSL_assert(dst);
    OPENSSL_assert(IsAligned(dst, 8));
    OPENSSL_assert(src);
    OPENSSL_assert(IsAligned(src, 8));

    const size_t size = BlockLengthInBytes / sizeof(uint64_t);
    for (size_t i = 0; i < size; ++i)
    {
        dst[i] = src[i];
    }
}

static inline void Transform(uint8_t* block, const uint8_t* table)
{
    OPENSSL_assert(block);
    OPENSSL_assert(IsAligned(block, 8));
    OPENSSL_assert(table);

    uint8_t buffer[BlockLengthInBytes] = {0};

    XorBlocks(buffer, GetAt(table, block[0x0] + 0x000));
    XorBlocks(buffer, GetAt(table, block[0x1] + 0x100));
    XorBlocks(buffer, GetAt(table, block[0x2] + 0x200));
    XorBlocks(buffer, GetAt(table, block[0x3] + 0x300));
    XorBlocks(buffer, GetAt(table, block[0x4] + 0x400));
    XorBlocks(buffer, GetAt(table, block[0x5] + 0x500));
    XorBlocks(buffer, GetAt(table, block[0x6] + 0x600));
    XorBlocks(buffer, GetAt(table, block[0x7] + 0x700));
    XorBlocks(buffer, GetAt(table, block[0x8] + 0x800));
    XorBlocks(buffer, GetAt(table, block[0x9] + 0x900));
    XorBlocks(buffer, GetAt(table, block[0xa] + 0xa00));
    XorBlocks(buffer, GetAt(table, block[0xb] + 0xb00));
    XorBlocks(buffer, GetAt(table, block[0xc] + 0xc00));
    XorBlocks(buffer, GetAt(table, block[0xd] + 0xd00));
    XorBlocks(buffer, GetAt(table, block[0xe] + 0xe00));
    XorBlocks(buffer, GetAt(table, block[0xf] + 0xf00));

    CopyBlock(block, buffer);
}

static inline void DirectTransform(uint8_t* block)
{
    Transform(block, gDirectTable);
}

static inline void InverseTransform(uint8_t* block)
{
    Transform(block, gInverseTable);
}

void EncryptBlocks(const uint8_t* roundKeys, uint8_t* blocks,
                   size_t numberOfBlocks)
{
    OPENSSL_assert(roundKeys);
    OPENSSL_assert(IsAligned(roundKeys, 8));
    OPENSSL_assert(blocks);
    OPENSSL_assert(IsAligned(blocks, 8));

    for (size_t i = 0; i < numberOfBlocks; ++i)
    {
        uint8_t* block = GetAt(blocks, i);
        unsigned round = 0;

        XorBlocks(block, GetAt(roundKeys, round));
        ++round;

        for (; round < NumberOfRounds; ++round)
        {
            DirectTransform(blocks);
            XorBlocks(blocks, GetAt(roundKeys, round));
        }
    }
}

void DecryptBlocks(const uint8_t* roundKeys, uint8_t* blocks,
                   size_t numberOfBlocks)
{
    OPENSSL_assert(roundKeys);
    OPENSSL_assert(IsAligned(roundKeys, 8));
    OPENSSL_assert(blocks);
    OPENSSL_assert(IsAligned(blocks, 8));

    for (size_t i = 0; i < numberOfBlocks; ++i)
    {
        uint8_t* block = GetAt(blocks, i);
        unsigned round = NumberOfRounds - 1;

        XorBlocks(block, GetAt(roundKeys, round));
        --round;

        DirectSubstituteBytes(block);
        InverseTransform(block);
        InverseTransform(block);
        XorBlocks(block, GetAt(roundKeys, round));
        --round;

        for (; round > 0; --round)
        {
            InverseTransform(block);
            XorBlocks(block, GetAt(roundKeys, round));
        }

        InverseSubstituteBytes(block);
        XorBlocks(block, GetAt(roundKeys, round));
    }
}

static inline uint8_t* ConstantAt(unsigned index)
{
    return GetAt(gConstants, index);
}

static inline void FeistelRoundWithoutSwap(uint8_t* left, uint8_t const* right,
                                           unsigned constantIndex)
{
    uint8_t buffer[BlockLengthInBytes] = {0};

    CopyBlock(buffer, right);
    XorBlocks(buffer, ConstantAt(constantIndex));
    DirectTransform(buffer);
    XorBlocks(left, buffer);
}

void ScheduleEncryptionRoundKeys(uint8_t* roundKeys, const uint8_t* key)
{
    OPENSSL_assert(roundKeys);
    OPENSSL_assert(IsAligned(roundKeys, 8));
    OPENSSL_assert(key);
    OPENSSL_assert(IsAligned(key, 8));

    unsigned i = 0;

    CopyBlock(GetAt(roundKeys, 0), GetAt(key, 0));
    CopyBlock(GetAt(roundKeys, 1), GetAt(key, 1));
    i += 2;

    for (unsigned constantIndex = 0; i != NumberOfRounds; i += 2)
    {
        uint8_t *left = GetAt(roundKeys, i), *right = GetAt(roundKeys, i + 1);

        CopyBlock(left, GetAt(roundKeys, i - 2));
        CopyBlock(right, GetAt(roundKeys, i - 1));

        for (size_t round = 0; round < NumberOfRoundsInKeySchedule; round += 2)
        {
            FeistelRoundWithoutSwap(right, left, constantIndex++);
            FeistelRoundWithoutSwap(left, right, constantIndex++);
        }
    }
}

void ScheduleDecryptionRoundKeys(uint8_t* roundKeys, const uint8_t* key)
{
    ScheduleEncryptionRoundKeys(roundKeys, key);

    for (unsigned i = 1; i <= NumberOfRounds - 2; ++i)
    {
        DirectSubstituteBytes(GetAt(roundKeys, i));
        InverseTransform(GetAt(roundKeys, i));
    }
}
