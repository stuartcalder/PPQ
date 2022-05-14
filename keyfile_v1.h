/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#ifndef SKC_KEYFILE_V1_H
#define SKC_KEYFILE_V1_H

#include "common.h"
#include "csprng.h"
#include "threefish512.h"

BASE_ALIGNAS(8) static const uint8_t SKC_KEYFILE_V1_ID [8] = {0xf3, 0xd7, 0xe1, 0xe0, 0x1a, 0xa7, 0x3c, 0xba};
#define SKC_KEYFILE_V1_ID          SKC_KEYFILE_V1_ID
#define SKC_KEYFILE_V1_ID_NBYTES   8
#define SKC_KEYFILE_V1_SALT_NBITS  512
#define SKC_KEYFILE_V1_SALT_NBYTES 64

#define R_(p) p BASE_RESTRICT
#define AL_   BASE_ALIGNAS(8)
BASE_BEGIN_C_DECLS

typedef struct {
  Skc_Keyfile_Input    input;
  Skc_UBI512           ubi;
  Skc_Threefish512_CTR ctr;
  uint64_t             enc_key  [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL_ uint8_t          auth_key [SKC_THREEFISH512_BLOCK_BYTES];
  AL_ uint8_t          hash_out [SKC_THREEFISH512_BLOCK_BYTES * 2];
} Skc_Keyfile_V1_Encrypt_Secret;

typedef struct {
  Skc_Keyfile_V1_Encrypt_Secret secret;
  uint64_t                      tf_tweak [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
  AL_ uint8_t                   ctr_iv   [SKC_THREEFISH512_CTR_IV_BYTES];
  //TODO
} Skc_Keyfile_V1_Encrypt;

typedef struct {
//TODO
} Skc_Keyfile_V1_Decrypt;

//TODO
SKC_API void
Skc_Keyfile_V1_encrypt
(R_(Skc_Keyfile_V1_Encrypt* const) ctx,
 R_(Base_MMap* const)              input_mmap,
 R_(Base_MMap* const)              output_mmap,
 R_(const char* const)             output_filepath);

//TODO
SKC_API void
Skc_Keyfile_V1_decrypt
(R_(Skc_Keyfile_V1_Decrypt* const) ctx,
 R_(Base_MMap* const)              input_mmap,
 R_(Base_MMap* const)              output_mmap,
 R_(const char* const)             output_filepath);

//TODO
SKC_API void
Skc_Keyfile_V1_dump_header
(R_(Base_MMap* const)  input_mmap,
 R_(const char* const) filepath);

BASE_END_C_DECLS
#undef AL_
#undef R_
#endif /* ! SKC_KEYFILE_V1_H */
