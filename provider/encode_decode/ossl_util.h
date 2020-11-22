#pragma once
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <ossl_gost/local/ossl_ptr.h>

inline
int convertBnToBuffer( const BIGNUM* bn, uint8_t* buf, size_t bufSize )
{
    OPENSSL_assert( bn );
    OPENSSL_assert( buf );

    size_t bytes = static_cast< size_t >( BN_num_bytes( bn ) );
    if( bytes > bufSize )
    {
        return 0;
    }
    OPENSSL_cleanse( buf, bufSize );
    return BN_bn2bin( bn, buf + bufSize - bytes );
}

inline
BIGNUM* convertBufferToBn( const uint8_t* buf, size_t bufSize )
{
    OPENSSL_assert( buf );
    OPENSSL_assert( bufSize  >  0 );
    OPENSSL_assert( bufSize <= 64 );

    uint8_t rbuf[ 64 ] = { 0 };
    for( size_t i = 0; i < bufSize; ++i )
    {
        rbuf[ bufSize - i - 1 ] = buf[ i ];
    }
    return BN_bin2bn( buf, static_cast< int >( bufSize ), nullptr );
}

inline
size_t serializePoint( BIGNUM* X, BIGNUM* Y, size_t coordSize,
                       uint8_t** pEncPoint )
{
    OPENSSL_assert( X );
    OPENSSL_assert( Y );
    OPENSSL_assert( coordSize > 0 );

    size_t pointSize = 2 * coordSize;
    ossl::MemPtr encPoint( ByteAlloc( pointSize ) );
    if( !encPoint )
    {
        return 0;
    }
    BN_bn2bin( X, encPoint.get() + coordSize );
    BN_bn2bin( Y, encPoint.get() );
    BUF_reverse( encPoint.get(), nullptr, pointSize );
    if( pEncPoint )
    {
        *pEncPoint = encPoint.release();
    }
    return pointSize;
}

inline
int convertAlgToHash( const int algNid )
{
    int hashNid = NID_undef;
    switch( algNid )
    {
    case NID_id_GostR3410_94:
    case NID_id_GostR3410_2001:
        hashNid = NID_id_GostR3411_94;
        break;
    case NID_id_GostR3410_2012_256:
        hashNid = NID_id_GostR3411_2012_256;
        break;
    case NID_id_GostR3410_2012_512:
        hashNid = NID_id_GostR3411_2012_512;
        break;
    default:
        break;
    }
    return hashNid;
}

inline
int convertAlgToHashParam( const int algNid )
{
    int hashParamNid = NID_undef;
    switch( algNid )
    {
    case NID_id_GostR3410_94:
    case NID_id_GostR3410_2001:
        hashParamNid = NID_id_GostR3411_94_CryptoProParamSet;
        break;
    case NID_id_GostR3410_2012_256:
        hashParamNid = NID_id_GostR3411_2012_256;
        break;
    case NID_id_GostR3410_2012_512:
        hashParamNid = NID_id_GostR3411_2012_512;
        break;
    default:
        break;
    }
    return hashParamNid;
}
