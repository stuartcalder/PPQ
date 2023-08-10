/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_THREEFISH512_H
#define PPQ_THREEFISH512_H

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <SSC/Macro.h>
#include <SSC/Memory.h>
#include <SSC/Operation.h>

#include "Macro.h"

#define PPQ_THREEFISH512_BLOCK_BITS           512 /* 512 bits per Threefish block. */
#define PPQ_THREEFISH512_BLOCK_BYTES          64  /* 64  bytes per Threefish block. */
#define PPQ_THREEFISH512_BLOCK_WORDS          8   /* 8 64-bit words per Threefish block. */
#define PPQ_THREEFISH512_KEY_BITS             PPQ_THREEFISH512_BLOCK_BITS  /* Same key bits as block bits. */
#define PPQ_THREEFISH512_KEY_BYTES            PPQ_THREEFISH512_BLOCK_BYTES /* Same key bytes as block bytes. */
#define PPQ_THREEFISH512_KEY_WORDS            PPQ_THREEFISH512_BLOCK_WORDS /* Same key words as block words. */
#define PPQ_THREEFISH512_TWEAK_BITS           128 /* 128 bits per Threefish tweak. */
#define PPQ_THREEFISH512_TWEAK_BYTES          16  /* 16 bytes per Threefish tweak. */
#define PPQ_THREEFISH512_TWEAK_WORDS          2   /* 2 64-bit words per Threefish tweak. */
#define PPQ_THREEFISH512_NUMBER_ROUNDS        72  /* 72 iterations of the round function per Threefish encrypt/decrypt. */
#define PPQ_THREEFISH512_NUMBER_SUBKEYS       19  /* 19 subkeys constitute the Threefish keyschedule. */
#define PPQ_THREEFISH512_EXTERNAL_KEY_WORDS   9   /* 8 + 1 parity word. */
#define PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS 3   /* 2 + 1 parity word. */
#define PPQ_THREEFISH512_CONSTANT_240         UINT64_C(0x1bd11bdaa9fc1a22)
#define PPQ_THREEFISH512COUNTERMODE_IV_BYTES  32  /* Counter Mode initialization vector bytes, copied into the second half of the block. */

#define AL64_ SSC_ALIGNAS(uint64_t)
#define R_    SSC_RESTRICT
SSC_BEGIN_C_DECLS

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Threefish512_calculateKeyScheduleParityWords ()
 *     Calculate and store the key-schedule parity words for the key and tweak.
 *     The parity words are at the end of both the key and the tweak, therefore
 *     the parity words are written to index 9 and index 3 of the key and tweak pointers
 *     respectively. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_Threefish512_calculateKeyScheduleParityWords(uint64_t* const R_ key, uint64_t* const R_ tweak);
/*==========================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Threefish512Static {}
 *     The Threefish512 Tweakable Block Cipher with a once-computed key schedule.
 *     Use this over PPQ_Threefish512Dynamic when you intend to encrypt large amounts
 *     of data without changing keys. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  uint64_t key_schedule [PPQ_THREEFISH512_KEY_WORDS * PPQ_THREEFISH512_NUMBER_SUBKEYS];
  uint64_t state        [PPQ_THREEFISH512_BLOCK_WORDS];
} PPQ_Threefish512Static;
#define PPQ_THREEFISH512STATIC_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Threefish512Static, 0)

PPQ_API void
PPQ_Threefish512Static_init(
 PPQ_Threefish512Static* const R_ ctx,
 uint64_t* const R_               key,  /* Address of PPQ_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
 uint64_t* const R_               twk); /* Address of PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */

/* Encipher one block, 64 bytes, and store it. Cannot fail. */
PPQ_API void
PPQ_Threefish512Static_encipher(
 PPQ_Threefish512Static* const R_ ctx,
 void* const                      ciphertext, /* Address to store the ciphertext block at. */
 const void* const                plaintext); /* Address to read the plaintext block from. */
/*==========================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Threefish512Dynamic {}
 *     The Threefish512 Tweakable Block Cipher with a dynamically-computed key schedule.
 *     Use this over PPQ_Threefish512Static when you intend to repeatedly re-key or change
 *     tweaks. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  uint64_t  state [PPQ_THREEFISH512_BLOCK_WORDS];
  uint64_t* extern_key;   /* Address of PPQ_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
  uint64_t* extern_tweak; /* Address of PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */
} PPQ_Threefish512Dynamic;
#define PPQ_THREEFISH512DYNAMIC_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Threefish512Dynamic, 0)

PPQ_INLINE void
PPQ_Threefish512Dynamic_init(
 PPQ_Threefish512Dynamic* const R_ ctx,
 uint64_t* const R_                key, /* Address of PPQ_THREEFISH512_EXTERNAL_KEY_WORDS little-endian uint64_t's. */
 uint64_t* const R_                twk) /* Address of PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS little-endian uint64_t's. */
{
  PPQ_Threefish512_calculateKeyScheduleParityWords(key, twk);
  ctx->extern_key   = key;
  ctx->extern_tweak = twk;
}

/* Encipher one block, 64 bytes, and store it. Cannot fail. */
PPQ_API void
PPQ_Threefish512Dynamic_encipher(
 PPQ_Threefish512Dynamic* const R_ ctx,
 void* const                       ciphertext, /* Address to store the encrypted block at. */
 const void* const                 plaintext); /* Address to read the plaintext block from. */
/*==========================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Threefish512CounterMode {}
 *     Threefish512 in Counter Mode. Use Threefish as a stream cipher.
 *     Initialize @threefish512 with PPQ_Threefish512Static_init() before
 *     calling PPQ_Threefish512CounterMode_init(). */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_Threefish512Static threefish512;
  AL64_ uint8_t          keystream [PPQ_THREEFISH512_BLOCK_BYTES];
  AL64_ uint8_t          buffer    [PPQ_THREEFISH512_BLOCK_BYTES];
} PPQ_Threefish512CounterMode;
#define PPQ_THREEFISH512COUNTERMODE_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Threefish512CounterMode, PPQ_THREEFISH512STATIC_NULL_LITERAL, {0}, {0})

/* Before calling PPQ_Threefish512CounterMode_init(), initialize @ctx->threefish512 with PPQ_Threefish512Static_init(). */
PPQ_API void
PPQ_Threefish512CounterMode_init(
 PPQ_Threefish512CounterMode* const R_ ctx,
 const void* const R_                  init_vec); /* Address of 32 pseudorandom bytes to use as an initialization vector. */

/* XOR input bytes with the Counter Mode keystream. Cannot fail. */
PPQ_API void
PPQ_Threefish512CounterMode_xorKeystream(
 PPQ_Threefish512CounterMode* const R_ ctx,
 void*                                 output,         /* Address to write @count bytes to. */
 const void*                           input,          /* Address to read  @count bytes from. */
 uint64_t                              count,          /* The number of bytes to XOR. */
 uint64_t                              kstream_start); /* Initial counter value. i.e. 0 means starting from the beginning of the keystream. */
/*==========================================================================================================*/

#if 0
PPQ_API void
PPQ_Threefish512Static_decipher(
 PPQ_Threefish512Static* const R_ ctx,
 void* const                      plaintext,   /* Address to store the plaintext block at. */
 const void* const                ciphertext); /* Address to read the ciphertext block from. */
#endif

SSC_END_C_DECLS
#undef R_
#undef AL64_

#endif /* ~ PPQ_THREEFISH512_H */
