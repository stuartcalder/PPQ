/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef SKC_THREEFISH512_H
#define SKC_THREEFISH512_H

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <Base/macros.h>
#include <Base/mem.h>
#include <Base/operations.h>
#include "macros.h"

#define SKC_THREEFISH512_BLOCK_BITS		512 /* 512 bits per Threefish block. */
#define SKC_THREEFISH512_BLOCK_BYTES		64  /* 64  bytes per Threefish block. */
#define SKC_THREEFISH512_BLOCK_WORDS		8   /* 8 64-bit words per Threefish block. */
#define SKC_THREEFISH512_KEY_BITS		SKC_THREEFISH512_BLOCK_BITS  /* Same key bits as block bits. */
#define SKC_THREEFISH512_KEY_BYTES		SKC_THREEFISH512_BLOCK_BYTES /* Same key bytes as block bytes. */
#define SKC_THREEFISH512_KEY_WORDS		SKC_THREEFISH512_BLOCK_WORDS /* Same key words as block words. */
#define SKC_THREEFISH512_TWEAK_BITS		128 /* 128 bits per Threefish tweak. */
#define SKC_THREEFISH512_TWEAK_BYTES		16  /* 16 bytes per Threefish tweak. */
#define SKC_THREEFISH512_TWEAK_WORDS		2   /* 2 64-bit words per Threefish tweak. */
#define SKC_THREEFISH512_NUMBER_ROUNDS		72  /* 72 iterations of the round function per Threefish encrypt/decrypt. */
#define SKC_THREEFISH512_NUMBER_SUBKEYS		19  /* 19 subkeys constitute the Threefish keyschedule. */
#define SKC_THREEFISH512_EXTERNAL_KEY_WORDS     9   /* 8 + 1 parity word. */
#define SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS   3   /* 2 + 1 parity word. */
#define SKC_THREEFISH512_CONSTANT_240		UINT64_C(0x1bd11bdaa9fc1a22)
#define SKC_THREEFISH512_CTR_IV_BYTES		32  /* Counter Mode initialization vector bytes, copied into the second half of the block. */

#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

/* Threefish-512 with a precomputed key schedule.
 *   Good for instances when you want to encrypt lots of data with one key
 *   Initialize with Skc_Threefish512_Static_init(). Provide a key and tweak. */
typedef struct {
  uint64_t key_schedule [SKC_THREEFISH512_KEY_WORDS * SKC_THREEFISH512_NUMBER_SUBKEYS];
  uint64_t state        [SKC_THREEFISH512_BLOCK_WORDS];
} Skc_Threefish512_Static;
#define SKC_THREEFISH512_STATIC_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Threefish512_Static, 0)

/* Threefish-512 with a dynamically computed key schedule.
 *   Used within Skein512 for efficiency, since the key schedule changes every round.
 *   Initialize with Skc_Threefish512_Dynamic_init(). Provide a key and tweak. */
typedef struct {
  uint64_t  state [SKC_THREEFISH512_BLOCK_WORDS];
  uint64_t* extern_key;   /* Address of SKC_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
  uint64_t* extern_tweak; /* Address of SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */
} Skc_Threefish512_Dynamic;
#define SKC_THREEFISH512_DYNAMIC_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Threefish512_Dynamic, 0)

/* Threefish-512 in Counter Mode. Use Threefish as a stream cipher.
 *   Initialize @threefish512 with Skc_Threefish512_Static_init() before
 *   calling Skc_Threefish512_CTR_init(). */
typedef struct {
  Skc_Threefish512_Static        threefish512;
  BASE_ALIGNAS(uint64_t) uint8_t keystream [SKC_THREEFISH512_BLOCK_BYTES];
  BASE_ALIGNAS(uint64_t) uint8_t buffer    [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_Threefish512_CTR;
#define SKC_THREEFISH512_CTR_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Threefish512_CTR, SKC_THREEFISH512_STATIC_NULL_LITERAL, {0}, {0})

/* THREEFISH PROCEDURES. */

/* Calculate and store the key schedule parity words for the key and tweak. */
BASE_API void
Skc_Threefish512_calc_ks_parity_words(uint64_t* const R_ key, uint64_t* const R_ twk);

/* Initialize Threefish512 data with a once-computed keyschedule. Cannot fail. */
SKC_API void
Skc_Threefish512_Static_init(
 Skc_Threefish512_Static* const R_ ctx,
 uint64_t* const R_                key_words,    /* Address of SKC_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
 uint64_t* const R_                tweak_words); /* Address of SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */

/* Encipher one block, 64 bytes, and store it. Cannot fail. */
SKC_API void
Skc_Threefish512_Static_encipher(
 Skc_Threefish512_Static* const R_ ctx,
 void* const                       ciphertext, /* Address to store the encrypted block at. */
 const void* const                 plaintext); /* Address to read the plaintext block from. */

/* Initialize Threefish512 data with a dynamically computed keyschedule. Cannot fail. */
SKC_INLINE void
Skc_Threefish512_Dynamic_init(
 Skc_Threefish512_Dynamic* const R_ ctx,
 uint64_t* const R_                 key, /* Address of SKC_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
 uint64_t* const R_                 twk) /* Address of SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */
{
  Skc_Threefish512_calc_ks_parity_words(key, twk);
  ctx->extern_key   = key;
  ctx->extern_tweak = twk;
}

/* Encipher one block, 64 bytes, and store it. Cannot fail. */
SKC_API void
Skc_Threefish512_Dynamic_encipher(
 Skc_Threefish512_Dynamic* const R_ ctx,
 void* const                        ciphertext, /* Address to store the encrypted block at. */
 const void* const                  plaintext); /* Address to read the plaintext block from. */

/* COUNTER MODE PROCEDURES. */

/* Counter Mode Initialization.
 * Before calling this, initialize @ctx->threefish512 with Skc_Threefish512_Static_init().
 * Cannot fail. */
SKC_API void
Skc_Threefish512_CTR_init(
 Skc_Threefish512_CTR* const R_ ctx,
 const void* const R_           init_vec); /* Address of 32 pseudorandom bytes to use as an initialization vectore for Threefish512 in Counter mode. */

/* XOR input bytes with the Counter Mode keystream. Cannot fail. */
SKC_API void
Skc_Threefish512_CTR_xor_keystream(
 Skc_Threefish512_CTR* const R_ ctx,
 void*                          output,         /* Address to write @count bytes to. */
 const void*                    input,          /* Address to read  @count bytes from. */
 uint64_t                       count ,         /* The number of bytes to XOR. */
 uint64_t                       starting_byte); /* Initial counter value. i.e. 0 means starting from the beginning of the keystream. */

BASE_END_C_DECLS
#undef R_

#endif /* ~ SKC_THREEFISH512_H */
