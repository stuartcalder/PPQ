/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef SKC_DRAGONFLY_V1_H
#define SKC_DRAGONFLY_V1_H

/* Base Headers */
#include <Base/macros.h>
#include <Base/mmap.h>
#include <Base/operations.h>
#include <Base/print.h>
/* Skc Headers */
#include "catena512.h"
#include "common.h"
#include "csprng.h"
#include "graph_hashing.h"
#include "macros.h"
#include "threefish512.h"

#define SKC_DRAGONFLY_V1_ID				"SSC_DRAGONFLY_V1"
#define SKC_DRAGONFLY_V1_ID_NBYTES			17 /* Including null-terminator. */
#define SKC_DRAGONFLY_V1_BLOCK_BITS			SKC_THREEFISH512_BLOCK_BITS
#define SKC_DRAGONFLY_V1_BLOCK_BYTES			SKC_THREEFISH512_BLOCK_BYTES
#define SKC_DRAGONFLY_V1_SALT_BITS			SKC_CATENA512_SALT_BITS
#define SKC_DRAGONFLY_V1_SALT_BYTES			SKC_CATENA512_SALT_BYTES
#define SKC_DRAGONFLY_V1_MAX_PASSWORD_BYTES		120
#define SKC_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES		(17 + /*Sizeof dragonfly_v1 id*/ \
							 8  + /*header size*/ \
							 4  + /*g_low, g_high, use_phi, lambda*/ \
							 SKC_THREEFISH512_TWEAK_BYTES + \
							 SKC_DRAGONFLY_V1_SALT_BYTES + \
							 SKC_THREEFISH512_CTR_IV_BYTES)
#define SKC_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES	16
#define SKC_DRAGONFLY_V1_TOTAL_HEADER_BYTES		(SKC_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES + SKC_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES)
#define SKC_DRAGONFLY_V1_MAC_BYTES			SKC_THREEFISH512_BLOCK_BYTES
#define SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES		(SKC_DRAGONFLY_V1_TOTAL_HEADER_BYTES + SKC_DRAGONFLY_V1_MAC_BYTES)

#define AL_ BASE_ALIGNAS(uint64_t)
SKC_API extern const uint8_t* const Skc_Dragonfly_V1_NoPhi_Cfg_g;
SKC_API extern const uint8_t* const Skc_Dragonfly_V1_Phi_Cfg_g;

#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

typedef struct {
  Skc_Catena512_Input  input;
  Skc_Catena512        catena512;
  Skc_Threefish512_CTR threefish512_ctr;
  Skc_UBI512           ubi512;
  uint64_t             enc_key  [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL_ uint8_t          auth_key [SKC_THREEFISH512_BLOCK_BYTES];
  AL_ uint8_t          hash_out [SKC_THREEFISH512_BLOCK_BYTES * 2];
} Skc_Dragonfly_V1_Encrypt_Secret;

SKC_INLINE void
Skc_Dragonfly_V1_Encrypt_Secret_init(Skc_Dragonfly_V1_Encrypt_Secret* ctx)
{
  Skc_Catena512_init(&ctx->catena512);
  Skc_UBI512_init(&ctx->ubi512);
  /* We don't initialize Threefish512_CTR yet because
   * we need the initialization vector. */
}

typedef struct {
  Skc_Dragonfly_V1_Encrypt_Secret secret;
  uint64_t                        tf_tweak       [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
  AL_ uint8_t                     ctr_iv         [SKC_THREEFISH512_CTR_IV_BYTES];
  AL_ uint8_t                     catena512_salt [SKC_THREEFISH512_BLOCK_BYTES * 2];
} Skc_Dragonfly_V1_Encrypt;
#define SKC_DRAGONFLY_V1_ENCRYPT_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Dragonfly_V1_Encrypt, 0)

SKC_INLINE void
Skc_Dragonfly_V1_Encrypt_init(Skc_Dragonfly_V1_Encrypt* ctx)
{
  Skc_Dragonfly_V1_Encrypt_Secret_init(&ctx->secret);
}

typedef struct {
  Skc_Threefish512_CTR	threefish512_ctr;
  Skc_Catena512         catena512;
  Skc_UBI512          	ubi512;
  uint64_t             	enc_key  [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL_ uint8_t 		auth_key [SKC_THREEFISH512_BLOCK_BYTES];
  AL_ uint8_t 		hash_buf [SKC_THREEFISH512_BLOCK_BYTES * 2];
  AL_ uint8_t 		mac      [SKC_COMMON_MAC_BYTES];
  uint8_t              	password [SKC_COMMON_PASSWORD_BUFFER_BYTES];
  int                  	password_size;
} Skc_Dragonfly_V1_Decrypt;
#define SKC_DRAGONFLY_V1_DECRYPT_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Dragonfly_V1_Decrypt, 0)

SKC_INLINE void
Skc_Dragonfly_V1_Decrypt_init(Skc_Dragonfly_V1_Decrypt* ctx)
{
  Skc_Catena512_init(&ctx->catena512);
  Skc_UBI512_init(&ctx->ubi512);
}

/* TODO: Document */
SKC_API void Skc_Dragonfly_V1_encrypt(
 Skc_Dragonfly_V1_Encrypt* const ctx,
 Base_MMap* const                input_mmap,
 Base_MMap* const                output_mmap,
 const char* const               output_filepath);

/* TODO: Document */
SKC_API void Skc_Dragonfly_V1_decrypt(
 Skc_Dragonfly_V1_Decrypt* const ctx,
 Base_MMap* const                input_mmap,
 Base_MMap* const                output_mmap,
 const char* const               output_filepath);

/* TODO: Document */
SKC_API void Skc_Dragonfly_V1_dump_header(
 Base_MMap* const  input_mmap,
 const char* const filepath);
#undef Str_t
#undef Map_t
#undef Decrypt_t
#undef Encrypt_t

BASE_END_C_DECLS
#undef R_
#undef AL_

#endif
