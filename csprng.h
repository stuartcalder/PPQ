#ifndef SKC_CSPRNG_H
#define SKC_CSPRNG_H

#include <Base/macros.h>
#include <Base/operations.h>
#include "macros.h"
#include "ubi512.h"
#define R_(p) p BASE_RESTRICT
#define AL_   BASE_ALIGNAS(uint64_t)
BASE_BEGIN_C_DECLS

typedef struct {
	Skc_UBI512  ubi512;
	AL_ uint8_t buffer [SKC_THREEFISH512_BLOCK_BYTES * 2];
	AL_ uint8_t seed   [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_CSPRNG;
#define SKC_CSPRNG_NULL_LITERAL \
 (Skc_CSPRNG){SKC_UBI512_NULL_LITERAL, {0}, {0}}

/* Skc_CSPRNG_init(context)
 * Obtain entropy from the OS, and use it as a seed for the RNG.
 *   @context: Address of Skc_CSPRNG struct.
 * No return value; could possibly fail fatally.
 */
BASE_INLINE void
Skc_CSPRNG_init
(Skc_CSPRNG* context)
{
  Skc_UBI512_init(&context->ubi512);
  Base_get_os_entropy(context->seed, sizeof(context->seed));
}

/* Skc_CSPRNG_del(context)
 * Securely zero over the RNG data.
 *   @context: Address of Skc_CSPRNG struct.
 * No return value; cannot fail.
 */
BASE_INLINE void
Skc_CSPRNG_del
(Skc_CSPRNG* context)
{ Base_secure_zero(context, sizeof(*context)); }

/* Skc_CSPRNG_reseed(context, entropy)
 * Re-seed using supplied entropy.
 *   @context: Address of Skc_CSPRNG struct.
 *   @entropy: 64 bytes of pseudorandom data to read and hash.
 * No return value; cannot fail.
 */
SKC_API void
Skc_CSPRNG_reseed
(R_(Skc_CSPRNG*) context,
 R_(const void*) entropy);

/* Skc_CSPRNG_os_reseed(context)
 * Re-seed, using entropy supplied by the OS.
 *   @context: Address of Skc_CSPRNG struct.
 * No return value; could possibly fail fatally.
 */
SKC_API void
Skc_CSPRNG_os_reseed
(Skc_CSPRNG* context);

/* Skc_CSPRNG_get(context, output, num_output_bytes)
 * Write @requested_bytes pseudo-random bytes to @output.
 *   @context        : Address of Skc_CSPRNG struct.
 *   @output         : Address to write output bytes to.
 *   @num_output_byte: Number of pseudo-random bytes to write.
 */
SKC_API void
Skc_CSPRNG_get
(R_(Skc_CSPRNG*) context,
 R_(void*)       output,
 uint64_t        num_output_bytes);

BASE_END_C_DECLS
#undef R_
#undef AL_

#endif /* ! */
