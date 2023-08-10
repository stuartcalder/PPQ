/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_UBI512_H
#define PPQ_UBI512_H

#include <stddef.h>
#include "Macro.h"
#include "Threefish512.h"

#define PPQ_UBI512_TWEAK_FIRST_BIT  UINT8_C(0x40)
#define PPQ_UBI512_TWEAK_FIRST_MASK UINT8_C(0xbf)
#define PPQ_UBI512_TWEAK_LAST_BIT   UINT8_C(0x80)
#define PPQ_UBI512_TYPEMASK_KEY     UINT8_C(0)  /* Key. */
#define PPQ_UBI512_TYPEMASK_CFG     UINT8_C(4)  /* Configuration. */
#define PPQ_UBI512_TYPEMASK_PRS     UINT8_C(8)  /* Personalization. */
#define PPQ_UBI512_TYPEMASK_PK      UINT8_C(12) /* Public-Key. */
#define PPQ_UBI512_TYPEMASK_KDF     UINT8_C(16) /* Key-Derivation-Function. */
#define PPQ_UBI512_TYPEMASK_NON     UINT8_C(20) /* Nonce. */
#define PPQ_UBI512_TYPEMASK_MSG     UINT8_C(48) /* Message. */
#define PPQ_UBI512_TYPEMASK_OUT     UINT8_C(63) /* Output. */

#define AL64_ SSC_ALIGNAS(uint64_t)
#define R_    SSC_RESTRICT
SSC_BEGIN_C_DECLS

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_UBI512 {}*/
/*     Data for utilizing the Threefish512 tweakable block cipher in Unique Block Iteration mode.
 *     PPQ_Threefish512Dynamic is used for efficiency, as the key schedule changes with every
 *     invocation of Threefish. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_Threefish512Dynamic threefish512;
  uint64_t                key_state   [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL64_ uint8_t	          msg_state   [PPQ_THREEFISH512_BLOCK_BYTES];
  uint64_t                tweak_state [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS];
} PPQ_UBI512;
#define PPQ_UBI512_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_UBI512, 0)
PPQ_INLINE void
PPQ_UBI512_initThreefishKeySchedule(PPQ_UBI512* const ctx)
{
  PPQ_Threefish512_calculateKeyScheduleParityWords(ctx->key_state, ctx->tweak_state);
}
PPQ_INLINE void
PPQ_UBI512_initThreefishPointers(PPQ_UBI512* const ctx)
{
  ctx->threefish512.extern_key   = ctx->key_state;
  ctx->threefish512.extern_tweak = ctx->tweak_state;
}
PPQ_INLINE void
PPQ_UBI512_init(PPQ_UBI512* const ctx)
{
  PPQ_UBI512_initThreefishKeySchedule(ctx);
  PPQ_UBI512_initThreefishPointers(ctx);
}
/*==================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_UBI512_chainConfig ()
 *     Configure the UBI data for the number of output bits. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_UBI512_chainConfig(
 PPQ_UBI512* const R_ context,
 const uint64_t       num_output_bits);
/*==================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_UBI512_chainMessage ()
 *     Process the input bytes into the UBI data. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_UBI512_chainMessage(
 PPQ_UBI512* const R_ context,
 const uint8_t* R_    input,       /* Where to read input from. */
 uint64_t             input_size); /* How many bytes to read. */
/*==================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_UBI512_chainOutput ()
 *     Process the message state and produce the Skein512 output */
/* PPQ_UBI512_chainNativeOutput ()
 *     Functionally the same as PPQ_UBI512_chainOutput(), but with a fixed output size
 *     of 64 bytes and slightly more optimized. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_UBI512_chainOutput(
 PPQ_UBI512* const R_ ctx,
 uint8_t* R_          output,       /* Where to write the output. */
 uint64_t             output_size); /* How many bytes to output. */
PPQ_API void
PPQ_UBI512_chainNativeOutput(
 PPQ_UBI512* const R_ ctx,
 uint8_t* R_          output); /* Where to write 64 bytes of hash output. */
/*==================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_UBI512_chainKey ()
 *     Process a 64 byte key for MAC construction. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_UBI512_chainKey(
 PPQ_UBI512* const R_ ctx,
 const uint8_t* R_    input_key);
/*==================================================================================================*/

SSC_END_C_DECLS
#undef R_
#undef AL64_

#endif // ~ PPQ_UBI512_MODE_H
