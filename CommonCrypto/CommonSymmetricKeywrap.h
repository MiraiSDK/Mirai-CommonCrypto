//
//  CommonSymmetricKeywrap.h
//  CommonCrypto
//
//  Created by Chen Yonghui on 4/10/15.
//  Copyright (c) 2015 Shanghai TinyNetwork Inc. All rights reserved.
//

#ifndef _CC_SYMKEYWRAP_H_
#define _CC_SYMKEYWRAP_H_

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>

#include <string.h>
#ifdef KERNEL
#include <machine/limits.h>
#else
#include <limits.h>
#include <stdlib.h>
#endif /* KERNEL */
#include <Availability.h>


#ifdef __cplusplus
extern "C" {
#endif
    
    enum {
        kCCWRAPAES = 1,
    };
    
    extern const uint8_t * const CCrfc3394_iv;
    extern const size_t CCrfc3394_ivLen ;
    
    typedef uint32_t CCWrappingAlgorithm;
    
    /*!
     @function  CCSymmetricKeyWrap
     @abstract  Wrap a symmetric key with a Key Encryption Key (KEK).
     
     @param algorithm       Currently only AES Keywrapping (rfc3394) is available
     via kCCWRAPAES
     @param iv              The initialization value to be used.  CCrfc3394_iv is
     available as a constant for the standard IV to use.
     @param ivLen           The length of the initialization value to be used.
     CCrfc3394_ivLen is available as a constant for the
     standard IV to use.
     @param kek             The Key Encryption Key to be used to wrap the raw key.
     @param kekLen          The length of the KEK in bytes.
     @param rawKey          The raw key bytes to be wrapped.
     @param rawKeyLen       The length of the key in bytes.
     @param wrappedKey      The resulting wrapped key produced by the function.
     The space for this must be provided by the caller.
     @param wrappedKeyLen   The length of the wrapped key in bytes.
     
     @discussion The algorithm chosen is determined by the algorithm parameter
     and the size of the key being wrapped (ie aes128 for 128 bit
     keys).
     
     @result    kCCBufferTooSmall indicates insufficent space in the wrappedKey
     buffer.
     kCCParamError can result from bad values for the kek, rawKey, and
     wrappedKey key pointers.
     */
    
    int
    CCSymmetricKeyWrap( CCWrappingAlgorithm algorithm,
                       const uint8_t *iv, const size_t ivLen,
                       const uint8_t *kek, size_t kekLen,
                       const uint8_t *rawKey, size_t rawKeyLen,
                       uint8_t  *wrappedKey, size_t *wrappedKeyLen);
    
    /*!
     @function  CCSymmetricKeyUnwrap
     @abstract  Unwrap a symmetric key with a Key Encryption Key (KEK).
     
     @param algorithm       Currently only AES Keywrapping (rfc3394) is available
     via kCCWRAPAES
     @param iv              The initialization value to be used.  CCrfc3394_iv is
     available as a constant for the standard IV to use.
     @param ivLen           The length of the initialization value to be used.
     CCrfc3394_ivLen is available as a constant for the
     standard IV to use.
     @param kek             The Key Encryption Key to be used to unwrap the raw key.
     @param kekLen          The length of the KEK in bytes.
     @param wrappedKey      The wrapped key bytes.
     @param wrappedKeyLen   The length of the wrapped key in bytes.
     @param rawKey          The resulting raw key bytes. The space for this must
     be provided by the caller.
     @param rawKeyLen       The length of the raw key in bytes.
     
     @discussion The algorithm chosen is determined by the algorithm parameter
     and the size of the key being wrapped (ie aes128 for 128 bit
     keys).
     
     @result    kCCBufferTooSmall indicates insufficent space in the rawKey buffer.
     kCCParamError can result from bad values for the kek, rawKey, and
     wrappedKey key pointers.
     */
    
    
    int
    CCSymmetricKeyUnwrap( CCWrappingAlgorithm algorithm,
                         const uint8_t *iv, const size_t ivLen,
                         const uint8_t *kek, size_t kekLen,
                         const uint8_t  *wrappedKey, size_t wrappedKeyLen,
                         uint8_t  *rawKey, size_t *rawKeyLen);
    
    /*!
     @function  CCSymmetricWrappedSize
     @abstract  Determine the buffer size required to hold a key wrapped with
     CCAESKeyWrap().
     
     @param     algorithm       Currently only AES Keywrapping (rfc3394) is
     available via kCCWRAPAES
     @param     rawKeyLen       The length of the key in bytes.
     @result    The length of the resulting wrapped key.
     */
    
    size_t
    CCSymmetricWrappedSize( CCWrappingAlgorithm algorithm, size_t rawKeyLen);
    
    /*!
     @function  CCSymmetricUnwrappedSize
     @abstract  Determine the buffer size required to hold a key unwrapped with
     CCAESKeyUnwrap().
     
     @param     algorithm       Currently only AES Keywrapping (rfc3394) is
     available via kCCWRAPAES
     @param     wrappedKeyLen   The length of the wrapped key in bytes.
     @result    The length of the resulting raw key.
     */
    
    size_t
    CCSymmetricUnwrappedSize( CCWrappingAlgorithm algorithm, size_t wrappedKeyLen);
    
#ifdef __cplusplus
}
#endif

#endif /* _CC_SYMKEYWRAP_H_ */