#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include "sysendian.h"
#include "argon2d/argon2.h"
#include "argon2d/core.h"

static const size_t OUTPUT_BYTES = 32;
static const unsigned int DEFAULT_ARGON2_FLAG = 2; //Same as ARGON2_DEFAULT_FLAGS

void argon2id_trtl_call(const void *input, void *output, unsigned int len)
{
    uint8_t saltLength = 16;

    argon2_context context;
    context.out = (uint8_t *)output;
    context.outlen = OUTPUT_BYTES;
    context.pwd = (uint8_t *)input;
    context.pwdlen = (uint32_t)len;

    /* Salt is the first 16 bytes of input */
    uint8_t salt[saltLength];
    memcpy(&salt, &input, saltLength);
    context.salt = salt;
    context.saltlen = saltLength;

    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG;
    context.m_cost = 512; /* 512 KB */
    context.lanes = 1;
    context.threads = 1;
    context.t_cost = 3; /* 3 Iterations */
    context.version = ARGON2_VERSION_13;

    argon2_ctx( &context, Argon2_id );
}

void argon2id_trtl_hash(const unsigned char* input, unsigned char* output, unsigned int len)
{
	argon2id_trtl_call(input, output, len);
}
