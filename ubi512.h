#ifndef SKC_UBI512_H
#define SKC_UBI512_H

#include <Base/macros.h>
#include "macros.h"
#include "threefish512.h"

#define SKC_UBI512_TWEAK_FIRST_BIT	UINT8_C(0x40)
#define SKC_UBI512_TWEAK_FIRST_MASK	UINT8_C(0xbf)
#define SKC_UBI512_TWEAK_LAST_BIT	UINT8_C(0x80)
#define SKC_UBI512_TYPEMASK_KEY		UINT8_C(0)
#define SKC_UBI512_TYPEMASK_CFG		UINT8_C(4)
#define SKC_UBI512_TYPEMASK_PRS		UINT8_C(8)
#define SKC_UBI512_TYPEMASK_PK		UINT8_C(12)
#define SKC_UBI512_TYPEMASK_KDF		UINT8_C(16)
#define SKC_UBI512_TYPEMASK_NON		UINT8_C(20)
#define SKC_UBI512_TYPEMASK_MSG		UINT8_C(48)
#define SKC_UBI512_TYPEMASK_OUT		UINT8_C(63)

#define WORD_ALIGN_ BASE_ALIGNAS(uint64_t)
typedef struct {
	Skc_Threefish512_Dynamic threefish512;
	uint64_t                 key_state   [SKC_THREEFISH512_EXTERNAL_KEY_WORDS];
	WORD_ALIGN_ uint8_t	 msg_state   [SKC_THREEFISH512_BLOCK_BYTES];
	uint64_t                 tweak_state [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
} Skc_UBI512;
#undef WORD_ALIGN_

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_DECLS
SKC_API void Skc_UBI512_chain_config (R_(Skc_UBI512* const) ctx, const uint64_t num_out_bits);
SKC_API void Skc_UBI512_chain_native_output (R_(Skc_UBI512* const) ctx, R_(uint8_t*) output);
SKC_API void Skc_UBI512_chain_message (R_(Skc_UBI512* const) ctx, R_(const uint8_t*) input, uint64_t num_in_bytes);
SKC_API void Skc_UBI512_chain_output (R_(Skc_UBI512* const) ctx, R_(uint8_t*) output, uint64_t num_out_byte);
SKC_API void Skc_UBI512_chain_key (R_(Skc_UBI512* const) ctx, R_(const uint8_t*) input);
BASE_END_DECLS
#undef R_

#endif // ~ SKC_UBI512_MODE_H
