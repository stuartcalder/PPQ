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

#define SKC_THREEFISH512_BLOCK_BITS		512
#define SKC_THREEFISH512_BLOCK_BYTES		64
#define SKC_THREEFISH512_BLOCK_WORDS		8
#define SKC_THREEFISH512_KEY_BITS		SKC_THREEFISH512_BLOCK_BITS
#define SKC_THREEFISH512_KEY_BYTES		SKC_THREEFISH512_BLOCK_BYTES
#define SKC_THREEFISH512_KEY_WORDS		SKC_THREEFISH512_BLOCK_WORDS
#define SKC_THREEFISH512_TWEAK_BITS		128
#define SKC_THREEFISH512_TWEAK_BYTES		16
#define SKC_THREEFISH512_TWEAK_WORDS		2
#define SKC_THREEFISH512_NUMBER_ROUNDS		72
#define SKC_THREEFISH512_NUMBER_SUBKEYS		19
#define SKC_THREEFISH512_EXTERNAL_KEY_WORDS	(SKC_THREEFISH512_KEY_WORDS + 1)
#define SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS	(SKC_THREEFISH512_TWEAK_WORDS + 1)
#define SKC_THREEFISH512_CONSTANT_240		UINT64_C(0x1bd11bdaa9fc1a22)
#define SKC_THREEFISH512_CTR_IV_BYTES		32

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_DECLS

/* Threefish-512 with a precomputed key schedule.
 *	Good for instances when you want to encrypt lots of data with one key.*/
typedef struct {
	uint64_t key_schedule   [SKC_THREEFISH512_KEY_WORDS * SKC_THREEFISH512_NUMBER_SUBKEYS];
	uint64_t state		[SKC_THREEFISH512_BLOCK_WORDS];
} Skc_Threefish512_Static;

#define SKC_THREEFISH512_STATIC_NULL_LITERAL (Skc_Threefish512_Static){0}

/* Threefish-512 with a dynamically computed key schedule.
 * 	Used within Skein512 for efficiency, since the key schedule changes every round. */
typedef struct {
	uint64_t  state [SKC_THREEFISH512_BLOCK_WORDS];
	uint64_t* extern_key;
	uint64_t* extern_tweak;
} Skc_Threefish512_Dynamic;

#define SKC_THREEFISH512_DYNAMIC_NULL_LITERAL (Skc_Threefish512_Dynamic){0}

#define ALIGN_ BASE_ALIGNAS(uint64_t)
typedef struct {
	Skc_Threefish512_Static  threefish512;
	ALIGN_ uint8_t	         keystream [SKC_THREEFISH512_BLOCK_BYTES];
	ALIGN_ uint8_t	         buffer    [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_Threefish512_CTR;
#undef ALIGN_

#define SKC_THREEFISH512_CTR_NULL_LITERAL (Skc_Threefish512_CTR){0}

/* Base Threefish procedures. */
SKC_API void Skc_Threefish512_Static_init (R_(Skc_Threefish512_Static* const) ctx,
                                           R_(uint64_t* const)                key,
					   R_(uint64_t* const)                tweak);
SKC_API void Skc_Threefish512_Static_encipher (R_(Skc_Threefish512_Static* const) ctx,
                                               uint8_t* const                     ciphertext,
					       const uint8_t* const               plaintext);
SKC_API void Skc_Threefish512_Dynamic_init  (R_(Skc_Threefish512_Dynamic* const) ctx,
                                             R_(uint64_t* const)                 key,
					     R_(uint64_t* const)                 tweak);
SKC_API void Skc_Threefish512_Dynamic_encipher (R_(Skc_Threefish512_Dynamic* const) ctx,
                                                uint8_t* const                      ciphertext,
						const uint8_t* const                plaintext);
/* Counter mode procedures. */
SKC_API void Skc_Threefish512_CTR_init (R_(Skc_Threefish512_CTR* const) ctx, R_(const uint8_t* const) init_vec);
SKC_API void Skc_Threefish512_CTR_xor_keystream (R_(Skc_Threefish512_CTR* const) ctx,
                                                 uint8_t*                        output,
						 const uint8_t*                  input,
						 uint64_t                        input_size,
						 uint64_t                        starting_byte);
BASE_END_DECLS
#undef R_

#endif /* ~ SKC_THREEFISH512_H */
