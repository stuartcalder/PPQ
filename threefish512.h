#ifndef SYMM_THREEFISH512_H
#define SYMM_THREEFISH512_H
#include "macros.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <shim/macros.h>
#include <shim/operations.h>

#define SYMM_THREEFISH512_BLOCK_BITS		512
#define SYMM_THREEFISH512_BLOCK_BYTES		64
#define SYMM_THREEFISH512_BLOCK_WORDS		8
#define SYMM_THREEFISH512_TWEAK_BITS		128
#define SYMM_THREEFISH512_TWEAK_BYTES		16
#define SYMM_THREEFISH512_TWEAK_WORDS		2
#define SYMM_THREEFISH512_NUMBER_ROUNDS		72
#define SYMM_THREEFISH512_NUMBER_SUBKEYS	19
#define SYMM_THREEFISH512_EXTERNAL_KEY_WORDS	(SYMM_THREEFISH512_BLOCK_WORDS + 1)
#define SYMM_THREEFISH512_EXTERNAL_TWEAK_WORDS	(SYMM_THREEFISH512_TWEAK_WORDS + 1)
#define SYMM_THREEFISH512_CONSTANT_240		UINT64_C (0x1bd11bdaa9fc1a22)
#define SYMM_THREEFISH512_CTR_IV_BYTES		32

typedef struct {
	uint64_t key_schedule 	[SYMM_THREEFISH512_BLOCK_WORDS * SYMM_THREEFISH512_NUMBER_SUBKEYS];
	uint64_t state		[SYMM_THREEFISH512_BLOCK_WORDS];
} Symm_Threefish512_Stored;
typedef struct {
	uint64_t   state	[SYMM_THREEFISH512_BLOCK_WORDS];
	uint64_t * stored_key;   /* -> External key words  */
	uint64_t * stored_tweak; /*-> External tweak words */
} Symm_Threefish512_On_Demand;
#define WORD_ALIGN_ SHIM_ALIGNAS (uint64_t)
typedef struct {
	Symm_Threefish512_Stored threefish_stored; 
	WORD_ALIGN_ uint8_t	 keystream [SYMM_THREEFISH512_BLOCK_BYTES];
	WORD_ALIGN_ uint8_t	 buffer    [SYMM_THREEFISH512_BLOCK_BYTES];
} Symm_Threefish512_CTR;
#undef WORD_ALIGN_

SHIM_BEGIN_DECLS

/* Base Threefish procedures. */
SYMM_API void
symm_threefish512_stored_rekey (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
			        uint64_t *                 SHIM_RESTRICT key,
			        uint64_t *                 SHIM_RESTRICT twk);
SYMM_API void
symm_threefish512_stored_cipher (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
			         uint8_t *                  SHIM_RESTRICT ctext,
			         uint8_t const *            SHIM_RESTRICT ptext);
SYMM_API void
symm_threefish512_ondemand_rekey (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				  uint64_t *                    SHIM_RESTRICT key,
				  uint64_t *                    SHIM_RESTRICT twk);

SYMM_API void
symm_threefish512_ondemand_cipher (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				   uint8_t *                     SHIM_RESTRICT ctext,
				   uint8_t const *               SHIM_RESTRICT ptext);
/* Higher-Level procedures. */
SYMM_API void
symm_threefish512_ctr_setiv (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
			     uint8_t const *         SHIM_RESTRICT iv);
SYMM_API void
symm_threefish512_ctr_xorcrypt (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
				uint8_t *                             output,
				uint8_t const *                       input,
				int64_t                               input_size,
				int64_t                               starting_byte);

SHIM_END_DECLS

#endif /* ~ SYMM_THREEFISH512_H */
