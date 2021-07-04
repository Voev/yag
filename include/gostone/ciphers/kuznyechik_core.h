#pragma once
#include <stddef.h>
#include <stdint.h>

void GsKuznyechikEncryptBlocks( const uint8_t* roundKeys,
                                uint8_t* blocks, 
                                size_t numberOfBlocks );

void GsKuznyechikDecryptBlocks( const uint8_t* roundKeys, 
                                uint8_t* blocks,
                                size_t numberOfBlocks );

void GsKuznyechikScheduleEncryptionRoundKeys( uint8_t* roundKeys, 
                                              const uint8_t* key );

void GsKuznyechikScheduleDecryptionRoundKeys( uint8_t* roundKeys, 
                                              const uint8_t* key );
