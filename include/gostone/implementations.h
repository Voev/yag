#pragma once
#include <openssl/types.h>

extern const OSSL_DISPATCH gGostR341112_256Funcs[];
extern const OSSL_DISPATCH gGostR341112_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_256Funcs[];
extern const OSSL_DISPATCH gGostR341012_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_256DerEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256PemEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256TextEncoderFuncs[];

extern const OSSL_DISPATCH gGostR341012_512DerEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_512PemEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_512TextEncoderFuncs[];
