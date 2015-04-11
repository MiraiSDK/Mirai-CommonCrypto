//
//  CommonCryptoError.h
//  CommonCrypto
//
//  Created by Chen Yonghui on 4/10/15.
//  Copyright (c) 2015 Shanghai TinyNetwork Inc. All rights reserved.
//

#ifndef CommonCrypto_CommonCryptoError_h
#define CommonCrypto_CommonCryptoError_h

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
    
    enum {
        kCCSuccess          = 0,
        kCCParamError       = -4300,
        kCCBufferTooSmall   = -4301,
        kCCMemoryFailure    = -4302,
        kCCAlignmentError   = -4303,
        kCCDecodeError      = -4304,
        kCCUnimplemented    = -4305,
        kCCOverflow         = -4306,
        kCCRNGFailure       = -4307,
    };
    typedef int32_t CCStatus;
    typedef int32_t CCCryptorStatus;
    
#if defined(__cplusplus)
}
#endif

#endif
