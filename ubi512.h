#ifndef SYMM_UBI512_H
#define SYMM_UBI512_H

#include <shim/macros.h>
#include "threefish512.h"
#include "macros.h"

#define SYMM_UBI512_TWEAK_FIRST_BIT	UINT8_C (0b01000000)
#define SYMM_UBI512_TWEAK_FIRST_MASK	UINT8_C (0b10111111)
#define SYMM_UBI512_TWEAK_LAST_BIT	UINT8_C (0b10000000)
#define SYMM_UBI512_TYPEMASK_KEY	UINT8_C (0)
#define SYMM_UBI512_TYPEMASK_CFG	UINT8_C (4)
#define SYMM_UBI512_TYPEMASK_PRS	UINT8_C (8)
#define SYMM_UBI512_TYPEMASK_PK		UINT8_C (12)
#define SYMM_UBI512_TYPEMASK_KDF	UINT8_C (16)
#define SYMM_UBI512_TYPEMASK_NON	UINT8_C (20)
#define SYMM_UBI512_TYPEMASK_MSG	UINT8_C (48)
#define SYMM_UBI512_TYPEMASK_OUT	UINT8_C (63)

#define WORD_ALIGN_ SHIM_ALIGNAS (uint64_t)
typedef struct Symm_UBI512_ {
	Symm_Threefish512_On_Demand threefish_ctx;
	uint64_t                    key_state   [SYMM_THREEFISH512_EXTERNAL_KEY_WORDS];
	WORD_ALIGN_ uint8_t	    msg_state   [SYMM_THREEFISH512_BLOCK_BYTES];
	uint64_t                    tweak_state [SYMM_THREEFISH512_EXTERNAL_TWEAK_WORDS];
} Symm_UBI512;
#undef WORD_ALIGN_
#define SYMM_UBI512_NULL_INIT { \
	.threefish_ctx = SYMM_THREEFISH512_ON_DEMAND_NULL_INIT, \
	.key_state = { 0 }, \
	.msg_state = { 0 }, \
	.tweak_state = { 0 } \
}

SHIM_BEGIN_DECLS

SYMM_API void
symm_ubi512_chain_config (Symm_UBI512 * SHIM_RESTRICT ctx,
			  int64_t const               num_out_bits);
SYMM_API void
symm_ubi512_chain_native_output (Symm_UBI512 * SHIM_RESTRICT ctx,
			         uint8_t *     SHIM_RESTRICT output);
SYMM_API void
symm_ubi512_chain_message (Symm_UBI512 *   SHIM_RESTRICT ctx,
			   uint8_t const * SHIM_RESTRICT input,
			   int64_t                       num_in_bytes);
SYMM_API void
symm_ubi512_chain_output (Symm_UBI512 * SHIM_RESTRICT ctx,
			  uint8_t *     SHIM_RESTRICT output,
			  int64_t                     num_out_bytes);
SYMM_API void
symm_ubi512_chain_key (Symm_UBI512 *   SHIM_RESTRICT ctx,
		       uint8_t const * SHIM_RESTRICT input);

SHIM_END_DECLS

#endif // ~ SYMM_UBI512_MODE_H
