#include <openssl/crypto.h>
#include <gostone/ciphers/kuznyechik_core.h>
#include <gostone/ciphers/kuznyechik_defs.h>

static
void substituteBytes( uint8_t* block, const uint8_t* sbox )
{
    OPENSSL_assert( block );
    OPENSSL_assert( sbox );

    for( size_t i = 0; i < BlockLengthInBytes; ++i )
    {
        block[ i ] = sbox[ block[ i ] ];
    }
}

static
void directSubstituteBytes( uint8_t* block )
{
    substituteBytes( block, gDirectPi );
}

static
void inverseSubstituteBytes( uint8_t* block )
{
    substituteBytes( block, gInversePi );
}

static
uint8_t* getAt( const uint8_t* table, size_t index )
{
    OPENSSL_assert( table );
    OPENSSL_assert( index < 0x1000 );

    return ( uint8_t* )( &table[ index * BlockLengthInBytes ] );
}

inline
void xorBlocks( uint8_t* dst, const uint8_t* src )
{
    OPENSSL_assert( dst );
    OPENSSL_assert( isAligned( dst, 8 ) );
    OPENSSL_assert( src );
    OPENSSL_assert( isAligned( src, 8 ) );

    const size_t size = BlockLengthInBytes / sizeof (uint64_t);

    for( size_t i = 0; i < size; ++i )
    {
        dst[i] ^= src[i];
    }

    return;
}

inline
void copyBlock( uint8_t* dst, const uint8_t* src )
{
    OPENSSL_assert( dst );
    OPENSSL_assert( isAligned( dst, 8 ) );
    OPENSSL_assert( src );
    OPENSSL_assert( isAligned( src, 8 ) );

    const size_t size = BlockLengthInBytes / sizeof (uint64_t);
    for( size_t i = 0; i < size; ++i )
    {
        dst[ i ] = src[ i ];
    }
}

static inline
void transform( uint8_t* block, const uint8_t* table )
{
    OPENSSL_assert( block );
    OPENSSL_assert( isAligned( block, 8 ) );
    OPENSSL_assert( table );

    uint8_t buffer[BlockLengthInBytes] = {0};

    xorBlocks(buffer, getAt(table, block[0x0] + 0x000));
    xorBlocks(buffer, getAt(table, block[0x1] + 0x100));
    xorBlocks(buffer, getAt(table, block[0x2] + 0x200));
    xorBlocks(buffer, getAt(table, block[0x3] + 0x300));
    xorBlocks(buffer, getAt(table, block[0x4] + 0x400));
    xorBlocks(buffer, getAt(table, block[0x5] + 0x500));
    xorBlocks(buffer, getAt(table, block[0x6] + 0x600));
    xorBlocks(buffer, getAt(table, block[0x7] + 0x700));
    xorBlocks(buffer, getAt(table, block[0x8] + 0x800));
    xorBlocks(buffer, getAt(table, block[0x9] + 0x900));
    xorBlocks(buffer, getAt(table, block[0xa] + 0xa00));
    xorBlocks(buffer, getAt(table, block[0xb] + 0xb00));
    xorBlocks(buffer, getAt(table, block[0xc] + 0xc00));
    xorBlocks(buffer, getAt(table, block[0xd] + 0xd00));
    xorBlocks(buffer, getAt(table, block[0xe] + 0xe00));
    xorBlocks(buffer, getAt(table, block[0xf] + 0xf00));

    copyBlock(block, buffer);
}

inline
void directTransform( uint8_t* block )
{
    transform( block, gDirectTable );
}

inline
void inverseTransform( uint8_t* block )
{
    transform( block, gInverseTable );
}

void encryptBlocks( const uint8_t* roundKeys,
                    uint8_t* blocks, size_t numberOfBlocks )
{
    OPENSSL_assert( roundKeys );
    OPENSSL_assert( isAligned( roundKeys, 8 ) );
    OPENSSL_assert( blocks );
    OPENSSL_assert( isAligned( blocks, 8 ) );

    for( size_t i = 0; i < numberOfBlocks; ++i )
    {
        uint8_t* block = getAt( blocks, i );
        unsigned round = 0;

        xorBlocks( block, getAt( roundKeys, round ) );
        ++round;

        for( ; round < NumberOfRounds; ++round )
        {
            directTransform( blocks );
            xorBlocks( blocks, getAt( roundKeys, round ) );
        }
    }
}

void decryptBlocks( const uint8_t* roundKeys, uint8_t* blocks,
                    size_t numberOfBlocks )
{
    OPENSSL_assert( roundKeys );
    OPENSSL_assert( blocks );
    OPENSSL_assert( isAligned( roundKeys, 8 ) );
    OPENSSL_assert( isAligned( blocks,    8 ) );

    for( size_t i = 0; i < numberOfBlocks; ++i )
    {
        uint8_t* block = getAt( blocks, i );
        unsigned round = NumberOfRounds - 1;

        xorBlocks( block, getAt( roundKeys, round ) );
        --round;

        directSubstituteBytes(block);
        inverseTransform(block);
        inverseTransform(block);
        xorBlocks(block, getAt(roundKeys, round));
        --round;

        for (; round > 0; --round)
        {
            inverseTransform(block);
            xorBlocks(block, getAt(roundKeys, round));
        }

        inverseSubstituteBytes(block);
        xorBlocks(block, getAt(roundKeys, round));
    }
}

inline
uint8_t* constantAt( unsigned index )
{
    return getAt( gConstants, index );
}

inline
void feistelRoundWithoutSwap( uint8_t* left, uint8_t const* right,
                              unsigned constantIndex )
{
    uint8_t buffer[ BlockLengthInBytes ];

    copyBlock( buffer, right );
    xorBlocks( buffer, constantAt( constantIndex ) );
    directTransform( buffer );
    xorBlocks( left, buffer );
}

void scheduleEncryptionRoundKeys( uint8_t* roundKeys, const uint8_t* key )
{
    OPENSSL_assert(roundKeys);
    OPENSSL_assert(isAligned(roundKeys, 8));
    OPENSSL_assert(key);
    OPENSSL_assert(isAligned(key, 8));

    unsigned i = 0;

    copyBlock(getAt(roundKeys, 0), getAt(key, 0));
    copyBlock(getAt(roundKeys, 1), getAt(key, 1));
    i += 2;

    for (unsigned constantIndex = 0; i != NumberOfRounds; i += 2) {
        uint8_t
            *left = getAt(roundKeys, i),
            *right = getAt(roundKeys, i + 1);

        copyBlock(left, getAt(roundKeys, i - 2));
        copyBlock(right, getAt(roundKeys, i - 1));

        for( size_t round = 0; round < NumberOfRoundsInKeySchedule; round += 2 )
        {
            feistelRoundWithoutSwap(right, left, constantIndex++);
            feistelRoundWithoutSwap(left, right, constantIndex++);
        }
    }
}

void scheduleDecryptionRoundKeys( uint8_t* roundKeys, const uint8_t* key )
{
    scheduleEncryptionRoundKeys( roundKeys, key );

    for( unsigned i = 1; i <= NumberOfRounds - 2; ++i )
    {
        directSubstituteBytes( getAt( roundKeys, i ) );
        inverseTransform( getAt( roundKeys, i ) );
    }
}
