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

#define WORD_ALIGN_ BASE_ALIGNAS(uint64_t)
#define AL_ BASE_ALIGNAS(8)
#define WORD_ALIGN_ AL_
SKC_API extern const uint8_t* const Skc_Dragonfly_V1_NoPhi_Cfg_g;
SKC_API extern const uint8_t* const Skc_Dragonfly_V1_Phi_Cfg_g;
#if 0
AL_ static const uint8_t Skc_Dragonfly_V1_Safe_Metadata  [SKC_THREEFISH512_BLOCK_BYTES] = {
	0x79,0xb5,0x79,0x1e,0x9a,0xac,0x02,0x64,
	0x2a,0xaa,0x99,0x1b,0xd5,0x47,0xed,0x14,
	0x74,0x4d,0x72,0xbf,0x13,0x22,0x54,0xc9,
	0xad,0xd6,0xb9,0xbe,0xe8,0x70,0x18,0xe2,
	0xaa,0x51,0x50,0xe2,0x1f,0xcd,0x90,0x19,
	0xb6,0x1f,0x0e,0xc6,0x05,0x00,0xd6,0xed,
	0x7c,0xf2,0x03,0x53,0xfd,0x42,0xa5,0xa3,
	0x7a,0x0e,0xbb,0xb4,0xa7,0xeb,0xdb,0xab
};
AL_ static const uint8_t Skc_Dragonfly_V1_Strong_Metadata  [SKC_THREEFISH512_BLOCK_BYTES] = {
	0x1f,0x23,0x89,0x58,0x4a,0x4a,0xbb,0xa5,
	0x9f,0x09,0xca,0xd4,0xef,0xac,0x43,0x1d,
	0xde,0x9a,0xb0,0xf8,0x69,0xaa,0x50,0xf3,
	0xed,0xcc,0xb4,0x7d,0x6d,0x4f,0x10,0xb9,
	0x8e,0x6a,0x68,0xab,0x6e,0x53,0xbc,0xd6,
	0xcf,0xfc,0xa7,0x63,0x94,0x44,0xbd,0xc7,
	0xb9,0x6d,0x09,0xf5,0x66,0x31,0xa3,0xc5,
	0xf3,0x26,0xeb,0x6f,0xa6,0xac,0xb0,0xa6
};
#endif

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_C_DECLS

typedef struct {
  Skc_Catena512_Input  input;
  Skc_Catena512        catena512;
  Skc_Threefish512_CTR threefish512_ctr;
  Skc_UBI512           ubi512;
  uint64_t             enc_key [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL_ uint8_t          auth_key [SKC_THREEFISH512_BLOCK_BYTES];
  AL_ uint8_t          hash_out [SKC_THREEFISH512_BLOCK_BYTES * 2];
} Skc_Dragonfly_V1_Encrypt_Secret;

#define Secret_t Skc_Dragonfly_V1_Encrypt_Secret
BASE_INLINE void
Skc_Dragonfly_V1_Encrypt_Secret_init
(Secret_t* ctx)
{
  Skc_Catena512_init(&ctx->catena512);
  Skc_UBI512_init(&ctx->ubi512);
  /* We don't initialize Threefish512_CTR yet because
   * we needs the initialization vector.
   */
}

typedef struct {
  Secret_t    secret;
  uint64_t    tf_tweak       [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
  AL_ uint8_t ctr_iv         [SKC_THREEFISH512_CTR_IV_BYTES];
  AL_ uint8_t catena512_salt [SKC_THREEFISH512_BLOCK_BYTES * 2];
} Skc_Dragonfly_V1_Encrypt;
#undef Secret_t
#define SKC_DRAGONFLY_V1_ENCRYPT_NULL_LITERAL (Skc_Dragonfly_V1_Encrypt){0}
BASE_INLINE void
Skc_Dragonfly_V1_Encrypt_init
(Skc_Dragonfly_V1_Encrypt* ctx)
{ Skc_Dragonfly_V1_Encrypt_Secret_init(&ctx->secret); }

typedef struct {
	Skc_Threefish512_CTR	threefish512_ctr;
	Skc_Catena512          	catena512;
	Skc_UBI512          	ubi512;
	uint64_t             	enc_key  [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
	WORD_ALIGN_ uint8_t 	auth_key [SKC_THREEFISH512_BLOCK_BYTES];
	WORD_ALIGN_ uint8_t 	hash_buf [SKC_THREEFISH512_BLOCK_BYTES * 2];
	WORD_ALIGN_ uint8_t 	mac      [SKC_COMMON_MAC_BYTES];
	uint8_t              	password [SKC_COMMON_PASSWORD_BUFFER_BYTES];
	int                  	password_size;
} Skc_Dragonfly_V1_Decrypt;
#define SKC_DRAGONFLY_V1_DECRYPT_NULL_LITERAL (Skc_Dragonfly_V1_Decrypt){0}
BASE_INLINE void
Skc_Dragonfly_V1_Decrypt_init
(Skc_Dragonfly_V1_Decrypt* ctx)
{
  Skc_Catena512_init(&ctx->catena512);
  Skc_UBI512_init(&ctx->ubi512);
}

#define R_Encrypt_t R_(Skc_Dragonfly_V1_Encrypt* const)
#define R_Decrypt_t R_(Skc_Dragonfly_V1_Decrypt* const)
#define R_Map_t     R_(Base_MMap* const)
#define R_Str_t   R_(const char* const)
SKC_API void
Skc_Dragonfly_V1_encrypt
(R_Encrypt_t ctx,
 R_Map_t     input_mmap,
 R_Map_t     output_mmap,
 R_Str_t     output_filepath);

SKC_API void
Skc_Dragonfly_V1_decrypt
(R_Decrypt_t ctx,
 R_Map_t     input_mmap,
 R_Map_t     output_mmap,
 R_Str_t     output_filepath);

SKC_API void
Skc_Dragonfly_V1_dump_header
(R_Map_t input_mmap,
 R_Str_t filepath);
#undef R_Str_t
#undef R_Map_t
#undef R_Decrypt_t
#undef R_Encrypt_t

BASE_END_C_DECLS
#undef R_
#undef AL_
#undef WORD_ALIGN_

#endif /* ! */
