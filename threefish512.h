#ifndef SYMM_THREEFISH512_H
#define SYMM_THREEFISH512_H
#include <shim/macros.h>
#include <shim/operations.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#define SYMM_THREEFISH512_BLOCK_BITS		512
#define SYMM_THREEFISH512_BLOCK_BYTES		(SYMM_THREEFISH512_BLOCK_BITS / CHAR_BIT)
#define SYMM_THREEFISH512_BLOCK_WORDS		(SYMM_THREEFISH512_BLOCK_BYTES / sizeof(uint64_t))
#define SYMM_THREEFISH512_TWEAK_BITS		128
#define SYMM_THREEFISH512_TWEAK_BYTES		(SYMM_THREEFISH512_TWEAK_BITS / CHAR_BIT)
#define SYMM_THREEFISH512_TWEAK_WORDS		(SYMM_THREEFISH512_TWEAK_BYTES / sizeof(uint64_t))
#define SYMM_THREEFISH512_NUMBER_ROUNDS		72
#define SYMM_THREEFISH512_NUMBER_SUBKEYS	19
#define SYMM_THREEFISH512_EXTERNAL_KEY_WORDS	(SYMM_THREEFISH512_BLOCK_WORDS + 1)
#define SYMM_THREEFISH512_EXTERNAL_TWEAK_WORDS	(SYMM_THREEFISH512_TWEAK_WORDS + 1)
#define SYMM_THREEFISH512_CONSTANT_240		UINT64_C (0x1bd11bdaa9fc1a22)
#define SYMM_THREEFISH512_CTR_IV_BYTES		(SYMM_THREEFISH512_BLOCK_BYTES / 2)

typedef struct SHIM_PUBLIC {
	uint64_t key_schedule 	[SYMM_THREEFISH512_BLOCK_WORDS * SYMM_THREEFISH512_NUMBER_SUBKEYS];
	uint64_t state		[SYMM_THREEFISH512_BLOCK_WORDS];
} Symm_Threefish512_Stored;

typedef struct SHIM_PUBLIC {
	uint64_t  state		[SYMM_THREEFISH512_BLOCK_WORDS];
	uint64_t *stored_key;  //-> External key words
	uint64_t *stored_tweak;//-> External tweak words
} Symm_Threefish512_On_Demand;

typedef struct SHIM_PUBLIC {
	Symm_Threefish512_Stored  threefish_stored; 
	uint8_t alignas(uint64_t) keystream [SYMM_THREEFISH512_BLOCK_BYTES];
	uint8_t alignas(uint64_t) buffer    [SYMM_THREEFISH512_BLOCK_BYTES];
} Symm_Threefish512_CTR;

SHIM_BEGIN_DECLS

/* Base Threefish procedures. */
void SHIM_PUBLIC
symm_threefish512_stored_rekey (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
			        uint64_t *                 SHIM_RESTRICT key,
			        uint64_t *                 SHIM_RESTRICT twk);
void SHIM_PUBLIC
symm_threefish512_stored_cipher (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
			         uint8_t *                  SHIM_RESTRICT ctext,
			         uint8_t const *            SHIM_RESTRICT ptext);
void SHIM_PUBLIC
symm_threefish512_ondemand_rekey (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				  uint64_t *                    SHIM_RESTRICT key,
				  uint64_t *                    SHIM_RESTRICT twk);

void SHIM_PUBLIC
symm_threefish512_ondemand_cipher (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				   uint8_t *                     SHIM_RESTRICT ctext,
				   uint8_t const *               SHIM_RESTRICT ptext);
/* Higher-Level procedures. */
void SHIM_PUBLIC
symm_threefish512_ctr_setiv (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
			     uint8_t const *         SHIM_RESTRICT iv);
void SHIM_PUBLIC
symm_threefish512_ctr_xorcrypt (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
				uint8_t *                             output,
				uint8_t const *                       input,
				uint64_t                              input_size,
				uint64_t                              starting_byte);
/*  */

SHIM_END_DECLS

#endif /* ~ SYMM_THREEFISH512_H */
