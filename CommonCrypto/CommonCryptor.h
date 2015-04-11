//
//  CommonCryptor.h
//  CommonCrypto
//
//  Created by Chen Yonghui on 4/10/15.
//  Copyright (c) 2015 Shanghai TinyNetwork Inc. All rights reserved.
//

#include <CommonCrypto/CommonCryptoError.h>

#ifndef _CC_COMMON_CRYPTOR_
#define _CC_COMMON_CRYPTOR_

#include <stdbool.h>
#include <stdint.h>
#ifndef KERNEL
#include <stddef.h>
#endif /* KERNEL */
#include <Availability.h>

#ifdef __cplusplus
extern "C" {
#endif
    
    typedef struct _CCCryptor *CCCryptorRef;
    enum {
        kCCEncrypt = 0,
        kCCDecrypt,
    };
    typedef uint32_t CCOperation;
    
    enum {
        kCCAlgorithmAES128 = 0,
        kCCAlgorithmAES = 0,
        kCCAlgorithmDES,
        kCCAlgorithm3DES,
        kCCAlgorithmCAST,
        kCCAlgorithmRC4,
        kCCAlgorithmRC2,
        kCCAlgorithmBlowfish
    };
    typedef uint32_t CCAlgorithm;
    
    enum {
        /* options for block ciphers */
        kCCOptionPKCS7Padding   = 0x0001,
        kCCOptionECBMode        = 0x0002
        /* stream ciphers currently have no options */
    };
    typedef uint32_t CCOptions;
    
    enum {
        kCCKeySizeAES128          = 16,
        kCCKeySizeAES192          = 24,
        kCCKeySizeAES256          = 32,
        kCCKeySizeDES             = 8,
        kCCKeySize3DES            = 24,
        kCCKeySizeMinCAST         = 5,
        kCCKeySizeMaxCAST         = 16,
        kCCKeySizeMinRC4          = 1,
        kCCKeySizeMaxRC4          = 512,
        kCCKeySizeMinRC2          = 1,
        kCCKeySizeMaxRC2          = 128,
        kCCKeySizeMinBlowfish     = 8,
        kCCKeySizeMaxBlowfish     = 56,
    };
    
    enum {
        /* AES */
        kCCBlockSizeAES128        = 16,
        /* DES */
        kCCBlockSizeDES           = 8,
        /* 3DES */
        kCCBlockSize3DES          = 8,
        /* CAST */
        kCCBlockSizeCAST          = 8,
        kCCBlockSizeRC2           = 8,
        kCCBlockSizeBlowfish      = 8,
    };
    
    
    enum {
        kCCContextSizeAES128	= 404,
        kCCContextSizeDES		= 240,
        kCCContextSize3DES		= 496,
        kCCContextSizeCAST		= 240,
        kCCContextSizeRC4		= 1072
    };
    
    
    
    CCCryptorStatus CCCryptorCreate(
                                    CCOperation op,             /* kCCEncrypt, etc. */
                                    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
                                    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
                                    const void *key,            /* raw key material */
                                    size_t keyLength,
                                    const void *iv,             /* optional initialization vector */
                                    CCCryptorRef *cryptorRef)  /* RETURNED */
    ;
    
    CCCryptorStatus CCCryptorCreateFromData(
                                            CCOperation op,             /* kCCEncrypt, etc. */
                                            CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
                                            CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
                                            const void *key,            /* raw key material */
                                            size_t keyLength,
                                            const void *iv,             /* optional initialization vector */
                                            const void *data,           /* caller-supplied memory */
                                            size_t dataLength,          /* length of data in bytes */
                                            CCCryptorRef *cryptorRef,   /* RETURNED */
                                            size_t *dataUsed)           /* optional, RETURNED */;
    
    CCCryptorStatus CCCryptorRelease(
                                     CCCryptorRef cryptorRef);
    
    CCCryptorStatus CCCryptorUpdate(
                                    CCCryptorRef cryptorRef,
                                    const void *dataIn,
                                    size_t dataInLength,
                                    void *dataOut,              /* data RETURNED here */
                                    size_t dataOutAvailable,
                                    size_t *dataOutMoved)       /* number of bytes written */;
    CCCryptorStatus CCCryptorFinal(
                                   CCCryptorRef cryptorRef,
                                   void *dataOut,
                                   size_t dataOutAvailable,
                                   size_t *dataOutMoved)       /* number of bytes written */;
    
    
    size_t CCCryptorGetOutputLength(
                                    CCCryptorRef cryptorRef,
                                    size_t inputLength,
                                    bool final);
    
    
    CCCryptorStatus CCCryptorReset(
                                   CCCryptorRef cryptorRef,
                                   const void *iv);
    
    
        
    CCCryptorStatus CCCrypt(
                            CCOperation op,         /* kCCEncrypt, etc. */
                            CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
                            CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
                            const void *key,
                            size_t keyLength,
                            const void *iv,         /* optional initialization vector */
                            const void *dataIn,     /* optional per op and alg */
                            size_t dataInLength,
                            void *dataOut,          /* data RETURNED here */
                            size_t dataOutAvailable,
                            size_t *dataOutMoved);
    
    
    /*!
     @enum       Cipher Modes
     @discussion These are the selections available for modes of operation for
     use with block ciphers.  If RC4 is selected as the cipher (a stream
     cipher) the only correct mode is kCCModeRC4.
     
     @constant kCCModeECB - Electronic Code Book Mode.
     @constant kCCModeCBC - Cipher Block Chaining Mode.
     @constant kCCModeCFB - Cipher Feedback Mode.
     @constant kCCModeOFB - Output Feedback Mode.
     @constant kCCModeXTS - XEX-based Tweaked CodeBook Mode.
     @constant kCCModeRC4 - RC4 as a streaming cipher is handled internally as a mode.
     @constant kCCModeCFB8 - Cipher Feedback Mode producing 8 bits per round.
     */
    
    
    enum {
        kCCModeECB		= 1,
        kCCModeCBC		= 2,
        kCCModeCFB		= 3,
        kCCModeCTR		= 4,
        kCCModeF8		= 5, // Unimplemented for now (not included)
        kCCModeLRW		= 6, // Unimplemented for now (not included)
        kCCModeOFB		= 7,
        kCCModeXTS		= 8,
        kCCModeRC4		= 9,
        kCCModeCFB8		= 10,
    };
    typedef uint32_t CCMode;
    
    /*!
     @enum       Padding for Block Ciphers
     @discussion These are the padding options available for block modes.
     
     @constant ccNoPadding -  No padding.
     @constant ccPKCS7Padding - PKCS7 Padding.
     */
    
    enum {
        ccNoPadding			= 0,
        ccPKCS7Padding		= 1,
    };
    typedef uint32_t CCPadding;
    
    /*!
     @enum       Mode options - Not currently in use.
     
     @discussion Values used to specify options for modes. This was used for counter
     mode operations in 10.8, now only Big Endian mode is supported.
     
     @constant kCCModeOptionCTR_LE - CTR Mode Little Endian.
     @constant kCCModeOptionCTR_BE - CTR Mode Big Endian.
     */
    
    enum {
        kCCModeOptionCTR_LE	= 0x0001, // Deprecated in iPhoneOS 6.0 and MacOSX10.9
        kCCModeOptionCTR_BE = 0x0002  // Deprecated in iPhoneOS 6.0 and MacOSX10.9
    };
    
    typedef uint32_t CCModeOptions;
    
    /*!
     @function   CCCryptorCreateWithMode
     @abstract   Create a cryptographic context.
     
     @param      op         Defines the basic operation: kCCEncrypt or
     kCCDecrypt.
     
     @param     mode		Specifies the cipher mode to use for operations.
     
     @param      alg        Defines the algorithm.
     
     @param		padding		Specifies the padding to use.
     
     @param      iv         Initialization vector, optional. Used by
     block ciphers with the following modes:
     
     Cipher Block Chaining (CBC)
     Cipher Feedback (CFB and CFB8)
     Output Feedback (OFB)
     Counter (CTR)
     
     If present, must be the same length as the selected
     algorithm's block size.  If no IV is present, a NULL
     (all zeroes) IV will be used.
     
     This parameter is ignored if ECB mode is used or
     if a stream cipher algorithm is selected.
     
     @param      key         Raw key material, length keyLength bytes.
     
     @param      keyLength   Length of key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.
     
     @param      tweak      Raw key material, length keyLength bytes. Used for the
     tweak key in XEX-based Tweaked CodeBook (XTS) mode.
     
     @param      tweakLength   Length of tweak key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.  For XTS
     this is the same length as the encryption key.
     
     @param		numRounds	The number of rounds of the cipher to use.  0 uses the default.
     
     @param      options    A word of flags defining options. See discussion
     for the CCModeOptions type.
     
     @param      cryptorRef  A (required) pointer to the returned CCCryptorRef.
     
     @result     Possible error returns are kCCParamError and kCCMemoryFailure.
     */
    
    
    CCCryptorStatus CCCryptorCreateWithMode(
                                            CCOperation 	op,				/* kCCEncrypt, kCCEncrypt */
                                            CCMode			mode,
                                            CCAlgorithm		alg,
                                            CCPadding		padding,
                                            const void 		*iv,			/* optional initialization vector */
                                            const void 		*key,			/* raw key material */
                                            size_t 			keyLength,
                                            const void 		*tweak,			/* raw tweak material */
                                            size_t 			tweakLength,
                                            int				numRounds,		/* 0 == default */
                                            CCModeOptions 	options,
                                            CCCryptorRef	*cryptorRef)	/* RETURNED */;
    
#ifdef __cplusplus
}
#endif

#endif  /* _CC_COMMON_CRYPTOR_ */