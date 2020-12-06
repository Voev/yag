#pragma once
#include <openssl/types.h>

extern const OSSL_DISPATCH gGostR341112_256Funcs[];
extern const OSSL_DISPATCH gGostR341112_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_256Funcs[];
extern const OSSL_DISPATCH gGostR341012_512Funcs[];

extern const OSSL_DISPATCH gGostR341012_256ToPkcs8DerEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToPkcs8PemEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToSubjPubKeyInfoDerEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToSubjPubKeyInfoPemEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToTypeSpecificDerEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToTypeSpecificPemEncoderFuncs[];
extern const OSSL_DISPATCH gGostR341012_256ToTextEncoderFuncs[];
