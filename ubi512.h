#ifndef SKC_UBI512_H
#define SKC_UBI512_H

#include <stddef.h>
#include <Base/macros.h>
#include "macros.h"
#include "threefish512.h"

#define SKC_UBI512_TWEAK_FIRST_BIT	UINT8_C(0x40)
#define SKC_UBI512_TWEAK_FIRST_MASK	UINT8_C(0xbf)
#define SKC_UBI512_TWEAK_LAST_BIT	UINT8_C(0x80)
#define SKC_UBI512_TYPEMASK_KEY		UINT8_C(0)  /* Key. */
#define SKC_UBI512_TYPEMASK_CFG		UINT8_C(4)  /* Configuration. */
#define SKC_UBI512_TYPEMASK_PRS		UINT8_C(8)  /* Personalization. */
#define SKC_UBI512_TYPEMASK_PK		UINT8_C(12) /* Public-Key. */
#define SKC_UBI512_TYPEMASK_KDF		UINT8_C(16) /* Key-Derivation-Function. */
#define SKC_UBI512_TYPEMASK_NON		UINT8_C(20) /* Nonce. */
#define SKC_UBI512_TYPEMASK_MSG		UINT8_C(48) /* Message. */
#define SKC_UBI512_TYPEMASK_OUT		UINT8_C(63) /* Output. */

#define R_(ptr) ptr BASE_RESTRICT
#define AL_     BASE_ALIGNAS(uint64_t)
BASE_BEGIN_C_DECLS
typedef struct {
	Skc_Threefish512_Dynamic threefish512;
	uint64_t                 key_state   [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
	AL_ uint8_t	         msg_state   [SKC_THREEFISH512_BLOCK_BYTES];
	uint64_t                 tweak_state [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
} Skc_UBI512;
#define SKC_UBI512_NULL_LITERAL (Skc_UBI512){0}

BASE_INLINE void
Skc_UBI512_init_tf_ks
(Skc_UBI512* const ctx)
{ Skc_Threefish512_calc_ks_parity_words(ctx->key_state, ctx->tweak_state); }

BASE_INLINE void
Skc_UBI512_init_tf_ptrs
(Skc_UBI512* const ctx)
{
  ctx->threefish512.extern_key   = ctx->key_state;
  ctx->threefish512.extern_tweak = ctx->tweak_state;
}

/* Base_UBI512_init()
 * TODO
 */
BASE_INLINE void
Skc_UBI512_init
(Skc_UBI512* const ctx)
{
  Skc_UBI512_init_tf_ks(ctx);
  Skc_UBI512_init_tf_ptrs(ctx);
}

/* Skc_UBI512_chain_config(context, num_output_bits)
 *   @context:         Address of Skc_UBI512 struct.
 *   @num_output_bits: Number of bits of outpit. (i.e. CHAR_BIT * (num output bytes)).
 * No return; cannot fail.
 */
SKC_API void
Skc_UBI512_chain_config
(R_(Skc_UBI512* const) context,
 const uint64_t        num_output_bits);

/* Skc_UBI512_chain_message(context, input, num_input_bytes)
 *   @context        : Address of Skc_UBI512 struct.
 *   @input          : Address to read input bytes from.
 *   @num_input_bytes: Number of bytes to read.
 * No return; Cannot fail.
 */
SKC_API void
Skc_UBI512_chain_message
(R_(Skc_UBI512* const) context,
 R_(const uint8_t*)    input,
 uint64_t              num_input_bytes);

/* Skc_UBI512_chain_output(context, output, num_output_bytes)
 *   @context: Address of Skc_UBI512 struct.
 *   @output : Address to write output bytes to.
 *   @num_output_bytes: Number of bytes to write.
 * No return; cannot fail.
 */
SKC_API void
Skc_UBI512_chain_output
(R_(Skc_UBI512* const) ctx,
 R_(uint8_t*)          output,
 uint64_t              num_out_byte);
 
/* Skc_UBI512_chain_native_output(context, output)
 *   @context: Address of Skc_UBI512 struct.
 *   @output : Address to write 64 bytes of hash output.
 * This procedure is functionally the same as $Skc_UBI512_chain_output
 * when the @output_size is 64.
 *
 * No return; cannot fail.
 */
SKC_API void
Skc_UBI512_chain_native_output
(R_(Skc_UBI512* const) ctx,
 R_(uint8_t*)          output);

/* Skc_UBI512_chain_key(context, key_input)
 *   @context  : Address of Skc_UBI512 struct.
 *   @key_input: Address of 64-byte key, for MAC construction.
 * No return; cannot fail.
 */
SKC_API void
Skc_UBI512_chain_key
(R_(Skc_UBI512* const) ctx,
 R_(const uint8_t*)    input);
BASE_END_C_DECLS
#undef R_
#undef AL_

#endif // ~ SKC_UBI512_MODE_H
