#pragma once
#include <stdint.h>

enum
{
    NumberOfRounds = 10,
    NumberOfRoundsInKeySchedule = 8,

    BlockLengthInBytes = 128 / 8,
    KeyLengthInBytes   = 256 / 8,
};

extern const uint8_t gConstants[];
extern const uint8_t gDirectPi[];
extern const uint8_t gInversePi[];
extern const uint8_t gDirectTable[];
extern const uint8_t gInverseTable[];
