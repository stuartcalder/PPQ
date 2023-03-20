/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef SKC_UBI512_H
#define SKC_UBI512_H

#include <stddef.h>
#include <Base/macros.h>
#include "macros.h"
#include "threefish512.h"

#define SKC_UBI512_TWEAK_FIRST_BIT  UINT8_C(0x40)
#define SKC_UBI512_TWEAK_FIRST_MASK UINT8_C(0xbf)
#define SKC_UBI512_TWEAK_LAST_BIT   UINT8_C(0x80)
#define SKC_UBI512_TYPEMASK_KEY	    UINT8_C(0)  /* Key. */
#define SKC_UBI512_TYPEMASK_CFG	    UINT8_C(4)  /* Configuration. */
#define SKC_UBI512_TYPEMASK_PRS	    UINT8_C(8)  /* Personalization. */
#define SKC_UBI512_TYPEMASK_PK	    UINT8_C(12) /* Public-Key. */
#define SKC_UBI512_TYPEMASK_KDF	    UINT8_C(16) /* Key-Derivation-Function. */
#define SKC_UBI512_TYPEMASK_NON	    UINT8_C(20) /* Nonce. */
#define SKC_UBI512_TYPEMASK_MSG	    UINT8_C(48) /* Message. */
#define SKC_UBI512_TYPEMASK_OUT	    UINT8_C(63) /* Output. */

#define AL_ BASE_ALIGNAS(uint64_t)
#define R_  BASE_RESTRICT
BASE_BEGIN_C_DECLS

typedef struct {
  Skc_Threefish512_Dynamic threefish512;
  uint64_t                 key_state   [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
  AL_ uint8_t	           msg_state   [SKC_THREEFISH512_BLOCK_BYTES];
  uint64_t                 tweak_state [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
} Skc_UBI512;
#define SKC_UBI512_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_UBI512, 0)

/* TODO */
SKC_INLINE void
Skc_UBI512_init_tf_ks(Skc_UBI512* const ctx)
{
  Skc_Threefish512_calc_ks_parity_words(ctx->key_state, ctx->tweak_state);
}

/* TODO */
SKC_INLINE void
Skc_UBI512_init_tf_ptrs(Skc_UBI512* const ctx)
{
  ctx->threefish512.extern_key   = ctx->key_state;
  ctx->threefish512.extern_tweak = ctx->tweak_state;
}

/* TODO */
SKC_INLINE void
Skc_UBI512_init(Skc_UBI512* const ctx)
{
  Skc_UBI512_init_tf_ks(ctx);
  Skc_UBI512_init_tf_ptrs(ctx);
}

/* Configure the UBI data for the number
 * of output bits. */
SKC_API void
Skc_UBI512_chain_config(
 Skc_UBI512* const R_ context,
 const uint64_t       num_output_bits);

/* Process the input bytes into the UBI data. */
SKC_API void
Skc_UBI512_chain_message(
 Skc_UBI512* const R_ context,
 const uint8_t* R_    input,            /* Where to read input from. */
 uint64_t             num_input_bytes); /* How many bytes to read. */

/* Note that Skc_UBI512_chain_output() and
 * Skc_UBI512_chain_native_output() are functionally the same
 * when @num_out_byte equals 64, but
 * Skc_UBI512_chain_native_output() is slightly more optimized. */

SKC_API void
Skc_UBI512_chain_output(
 Skc_UBI512* const R_ ctx,
 uint8_t* R_          output,        /* Where to write the output. */
 uint64_t             num_out_byte); /* How many bytes to output. */
 
SKC_API void
Skc_UBI512_chain_native_output(
 Skc_UBI512* const R_ ctx,
 uint8_t* R_          output); /* Where to write 64 bytes of hash output. */

/* Process a 64-byte key, for MAC construction. */
SKC_API void
Skc_UBI512_chain_key(
 Skc_UBI512* const R_ ctx,
 const uint8_t* R_    input);

BASE_END_C_DECLS
#undef R_
#undef AL_

#endif // ~ SKC_UBI512_MODE_H
