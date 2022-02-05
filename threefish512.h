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
#define SKC_THREEFISH512_EXTERNAL_KEY_WORDS     9 /*+ 1 parity word.*/
#define SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS   3 /*+ 1 parity word.*/
#define SKC_THREEFISH512_CONSTANT_240		UINT64_C(0x1bd11bdaa9fc1a22)
#define SKC_THREEFISH512_CTR_IV_BYTES		32

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_C_DECLS

/* Threefish-512 with a precomputed key schedule.
 *   Good for instances when you want to encrypt lots of data with one key
 *   Initialize with Skc_Threefish512_Static_init. Provide a key and tweak.
 */
typedef struct {
	uint64_t key_schedule   [SKC_THREEFISH512_KEY_WORDS * SKC_THREEFISH512_NUMBER_SUBKEYS];
	uint64_t state		[SKC_THREEFISH512_BLOCK_WORDS];
} Skc_Threefish512_Static;
#define SKC_THREEFISH512_STATIC_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Threefish512_Static, 0)

/* Threefish-512 with a dynamically computed key schedule.
 * 	Used within Skein512 for efficiency, since the key schedule changes every round. */
typedef struct {
	uint64_t  state [SKC_THREEFISH512_BLOCK_WORDS];
	uint64_t* extern_key;
	uint64_t* extern_tweak;
} Skc_Threefish512_Dynamic;
#define SKC_THREEFISH512_DYNAMIC_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Threefish512_Dynamic, 0)

#define AL_ BASE_ALIGNAS(uint64_t)
typedef struct {
	Skc_Threefish512_Static threefish512;
	AL_ uint8_t             keystream [SKC_THREEFISH512_BLOCK_BYTES];
	AL_ uint8_t	        buffer    [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_Threefish512_CTR;
#undef AL_

#define SKC_THREEFISH512_CTR_NULL_LITERAL BASE_COMPOUND_LITERAL(SKC_THREEFISH512_STATIC_NULL_LITERAL, {0}, {0})

/* Base Threefish procedures. */

/* Skc_Threefish512_calc_ks_parity_words()
 * TODO
 */
SKC_API void
Skc_Threefish512_calc_ks_parity_words
(R_(uint64_t* const) key,
 R_(uint64_t* const) twk);

/* Skc_Threefish512_Static_init(context, key_words, tweak_words)
 * Initialize Threefish512 data with a once-computed keyschedule.
 *   @context:     Address of Skc_Threefish512_Static struct.
 *   @key_words:   Address of 64-bit little-endian key words.   (SKC_THREEFISH512_EXTERNAL_KEY_WORDS   64-bit words).
 *   @tweak_words: Address of 64-bit little-endian tweak words. (SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS 64-bit words).
 * No return; cannot fail.
 */
SKC_API void
Skc_Threefish512_Static_init
(R_(Skc_Threefish512_Static* const) context,
 R_(uint64_t* const)                key_words,
 R_(uint64_t* const)                tweak_words);

/* Skc_Threefish512_Static_encipher(context, ciphertext, plaintext)
 * Encipher one block, 64 bytes, and store it.
 *   @context:    Address of Skc_Threefish512_Static struct.
 *   @ciphertext: Address to store the encrypted block at.
 *   @plaintext:  Address to read the plaintext block from.
 * No return; cannot fail.
 */
SKC_API void
Skc_Threefish512_Static_encipher
(R_(Skc_Threefish512_Static* const) context,
 void* const                        ciphertext,
 const void* const                  plaintext);

/* Skc_Threefish512_Dynamic_init()
 * TODO
 */
BASE_INLINE void
Skc_Threefish512_Dynamic_init
(R_(Skc_Threefish512_Dynamic* const) ctx,
 R_(uint64_t* const)                 key,
 R_(uint64_t* const)                 twk)
{
  Skc_Threefish512_calc_ks_parity_words(key, twk);
  ctx->extern_key   = key;
  ctx->extern_tweak = twk;
}

/* Skc_Threefish512_Dynamic_encipher(context, ciphertext, plaintext)
 * Encipher one block, 64 bytes, and store it.
 *   @context:    Address of Skc_Threefish512_Dynamic struct.
 *   @ciphertext: Address to store the encrypted block at.
 *   @plaintext:  Address to read the plaintext block from.
 * No return; cannot fail.
 */
SKC_API void
Skc_Threefish512_Dynamic_encipher
(R_(Skc_Threefish512_Dynamic* const) ctx,
 void* const                         ciphertext,
 const void* const                   plaintext);

/* Counter mode procedures. */

/* Skc_Threefish512_CTR_init(context, initialization_vector)
 *   @context:               Address of Skc_Threefish512_CTR struct.
 *   @initialization_vector: Address of 32 pseudorandom bytes to use as CTR IV for Threefish512-CTR.
 *
 * Before calling this, initialize Skc_Threefish512_CTR.threefish512 with $Skc_Threefish512_Static_init.
 *
 * No return; cannot fail.
 */
SKC_API void
Skc_Threefish512_CTR_init
(R_(Skc_Threefish512_CTR* const) ctx,
 R_(const void* const) init_vec);

/* Skc_Threefish512_CTR_xor_keystream(context, output, input, input_size, starting_byte)
 *   @context:       Address of Skc_Threefish512_CTR struct.
 *   @output:        Address to being writing output to. Write @input_size here.
 *   @input:         Address to begin reading input from. Read @input_size from here.
 *   @input_size:    Number of bytes to XOR.
 *   @starting_byte: Initial CTR mode counter value. i.e. 0 means start from the beginning
 *                   of the keystream.
 */
SKC_API void
Skc_Threefish512_CTR_xor_keystream
(R_(Skc_Threefish512_CTR* const) ctx,
 void*                           output,
 const void*                     input,
 uint64_t                        input_size,
 uint64_t                        starting_byte);

BASE_END_C_DECLS
#undef R_

#endif /* ~ SKC_THREEFISH512_H */
