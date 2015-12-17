//
//  CommonDigest.m
//  CommonCrypto
//
//  Created by Chen Yonghui on 4/10/15.
//  Copyright (c) 2015 Shanghai TinyNetwork Inc. All rights reserved.
//

#import "CommonDigest.h"
#include "md5.h"
#include "sha1.h"

unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md)
{
    md5_state_t md5;
    md5_init(&md5);
    md5_append(&md5,data,len);
    md5_finish(&md5,md);
    return NULL;
}

unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md)
{
    SHA1Context sha1;
    SHA1Init(&sha1);
    SHA1Update(&sha1, data, len);
    SHA1Final(&sha1, md);
    return NULL;
}