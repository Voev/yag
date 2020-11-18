#pragma once
#include <stdint.h>

enum
{
    NumberOfRounds = 12,
    Streebog256LengthInBytes = 32,
    Streebog512LengthInBytes = 64,
    BlockLengthInBytes = 64,
    BlockLengthInUInt64 = BlockLengthInBytes / sizeof( uint64_t )
};

extern const uint64_t gConst0[];
extern const uint64_t gConst512[];
extern const uint64_t C[];
extern const uint64_t Ax[ 8 ][ 256 ];
