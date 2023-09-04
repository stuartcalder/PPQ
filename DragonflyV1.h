/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_DRAGONFLY_V1_H
#define PPQ_DRAGONFLY_V1_H

/* SSC Headers */
#include <SSC/Macro.h>
#include <SSC/MemMap.h>
#include <SSC/Operation.h>
#include <SSC/Print.h>
/* PPQ Headers */
#include "Macro.h"
#include "Catena512.h"
#include "Common.h"
#include "CSPRNG.h"
#include "GraphHash.h"
#include "Threefish512.h"

#define PPQ_DRAGONFLY_V1_ID                      "SSC_DRAGONFLY_V1" /* C-string that prefixes Dragonfly_V1 encrypted files. */
#define PPQ_DRAGONFLY_V1_ID_NBYTES               17 /* Including null-terminator. */
#define PPQ_DRAGONFLY_V1_BLOCK_BITS              PPQ_THREEFISH512_BLOCK_BITS
#define PPQ_DRAGONFLY_V1_BLOCK_BYTES             PPQ_THREEFISH512_BLOCK_BYTES
#define PPQ_DRAGONFLY_V1_SALT_BITS               PPQ_CATENA512_SALT_BITS
#define PPQ_DRAGONFLY_V1_SALT_BYTES              PPQ_CATENA512_SALT_BYTES
#define PPQ_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES  (PPQ_DRAGONFLY_V1_ID_NBYTES +\
                                                  8 + /*header size*/\
                                                  4 + /*g_low, g_high, use_phi, lambda*/\
                                                  PPQ_THREEFISH512_TWEAK_BYTES +\
                                                  PPQ_DRAGONFLY_V1_SALT_BYTES +\
						  PPQ_THREEFISH512COUNTERMODE_IV_BYTES)
#define PPQ_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES  16
#define PPQ_DRAGONFLY_V1_TOTAL_HEADER_BYTES       (PPQ_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES + PPQ_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES)
#define PPQ_DRAGONFLY_V1_MAC_BYTES                PPQ_THREEFISH512_BLOCK_BYTES
#define PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES   (PPQ_DRAGONFLY_V1_TOTAL_HEADER_BYTES + PPQ_DRAGONFLY_V1_MAC_BYTES)

#define AL64_ SSC_ALIGNAS(uint64_t)
PPQ_API extern const uint8_t* const PPQ_Dragonfly_V1_NoPhi_Cfg_g;
PPQ_API extern const uint8_t* const PPQ_Dragonfly_V1_Phi_Cfg_g;

#define R_ SSC_RESTRICT
SSC_BEGIN_C_DECLS

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_Catena512Input          input;
  PPQ_Catena512               catena512;
  PPQ_Threefish512CounterMode threefish512_ctr;
  PPQ_UBI512                  ubi512;
  uint64_t                    enc_key  [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL64_ uint8_t               auth_key [PPQ_THREEFISH512_BLOCK_BYTES];
  AL64_ uint8_t               hash_out [PPQ_THREEFISH512_BLOCK_BYTES * 2];
} PPQ_DragonflyV1EncryptSecret;

PPQ_INLINE void
PPQ_DragonflyV1EncryptSecret_init(PPQ_DragonflyV1EncryptSecret* ctx)
{
  PPQ_Catena512_init(&ctx->catena512);
  PPQ_UBI512_init(&ctx->ubi512);
  /* We don't initialize Threefish512_CTR yet because
   * we need the initialization vector. */
}

typedef struct {
  PPQ_DragonflyV1EncryptSecret secret;
  uint64_t                     tf_tweak       [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS];
  AL64_ uint8_t                ctr_iv         [PPQ_THREEFISH512COUNTERMODE_IV_BYTES];
  AL64_ uint8_t                catena512_salt [PPQ_THREEFISH512_BLOCK_BYTES * 2];
} PPQ_DragonflyV1Encrypt;
#define PPQ_DRAGONFLYV1ENCRYPT_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_DragonflyV1Encrypt, 0)

PPQ_INLINE void
PPQ_DragonflyV1Encrypt_init(PPQ_DragonflyV1Encrypt* ctx)
{
  PPQ_DragonflyV1EncryptSecret_init(&ctx->secret);
}
/*=============================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_Threefish512CounterMode threefish512_ctr;
  PPQ_Catena512               catena512;
  PPQ_UBI512                  ubi512;
  uint64_t                    enc_key  [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL64_ uint8_t               auth_key [PPQ_THREEFISH512_BLOCK_BYTES];
  AL64_ uint8_t               hash_buf [PPQ_THREEFISH512_BLOCK_BYTES * 2];
  AL64_ uint8_t               mac      [PPQ_COMMON_MAC_BYTES];
  uint8_t                     password [PPQ_COMMON_PASSWORD_BUFFER_BYTES];
  int                         password_size;
} PPQ_DragonflyV1Decrypt;
#define PPQ_DRAGONFLYV1DECRYPT_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_DragonflyV1Decrypt, 0)

PPQ_INLINE void
PPQ_DragonflyV1Decrypt_init(PPQ_DragonflyV1Decrypt* ctx)
{
  PPQ_Catena512_init(&ctx->catena512);
  PPQ_UBI512_init(&ctx->ubi512);
}
/*=============================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_DragonflyV1_encrypt ()
 *     Given an initialized input SSC_MemMap, @input_mmap, initialize the output
 *     SSC_MemMap @output_mmap and encrypt the data mapped in @input_mmap storing the
 *     ciphertext data into @output_mmap. Provide @output_filepath to allow for removing
 *     files from the filesystem in case the encryption fails. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void PPQ_DragonflyV1_encrypt(
 PPQ_DragonflyV1Encrypt* const R_ ctx,
 SSC_MemMap* const R_             input_mmap,
 SSC_MemMap* const R_             output_mmap,
 const char* const R_             output_filepath);
/*=============================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_DragonflyV1_decrypt ()
 *     Given a
 */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void PPQ_DragonflyV1_decrypt(
 PPQ_DragonflyV1Decrypt* const R_ ctx,
 SSC_MemMap* const R_             input_mmap,
 SSC_MemMap* const R_             output_mmap,
 const char* const R_             output_filepath);
/*=============================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void PPQ_DragonflyV1_dumpHeader(
 SSC_MemMap* const R_ input_mmap,
 const char* const    filepath);
/*=============================================================================================*/

SSC_END_C_DECLS
#undef R_
#undef AL_

#endif
