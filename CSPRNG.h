/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_CSPRNG_H
#define PPQ_CSPRNG_H

#include <SSC/Macro.h>
#include <SSC/Operation.h>
#include "Macro.h"
#include "Ubi512.h"
#define AL64_ SSC_ALIGNAS(uint64_t)
#define R_    SSC_RESTRICT
SSC_BEGIN_C_DECLS

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_CSPRNG {}
 *     Use the Skein Cryptographic Hash Function as a secure pseudorandom number generator.
 *         Overview: Hash the 64 pseudorandom bytes of @seed, producing 128 pseudorandom bytes
 *         in @buffer. From there 64 bytes of @buffer will be copied back into @seed to prepare
 *         for the next invocation, while the other 64 bytes of @buffer will be copied out. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_UBI512    ubi512;
  AL64_ uint8_t buffer [PPQ_THREEFISH512_BLOCK_BYTES * 2];
  AL64_ uint8_t seed   [PPQ_THREEFISH512_BLOCK_BYTES];
} PPQ_CSPRNG;
#define PPQ_CSPRNG_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_CSPRNG, PPQ_UBI512_NULL_LITERAL, {0}, {0})
/* Obtain entropy from the OS, and use it as a seed for the RNG. */
PPQ_INLINE void
PPQ_CSPRNG_init(PPQ_CSPRNG* ctx)
{
  PPQ_UBI512_init(&ctx->ubi512);
  SSC_getEntropy(ctx->seed, sizeof(ctx->seed));
}
/* Securely zero over the RNG data. */
PPQ_INLINE void
PPQ_CSPRNG_del(PPQ_CSPRNG* ctx)
{
  SSC_secureZero(ctx, sizeof(*ctx));
}
/*=================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_CSPRNG_reseed ()
 *     Obtains 64 bytes of user-provided @entropy and places it into @ctx->buffer, then
 *     copies @ctx->seed into the last 64 bytes of @ctx->buffer, hashes them into 64 pseudorandom
 *     bytes that are copied back into @ctx->seed.
 *     ->void
 * PPQ_CSPRNG_reseedFromOS ()
 *     Obtains 64 bytes of entropy from the OS and places it into @ctx->buffer, then
 *     copies @ctx->seed into the last 64 bytes of @ctx->buffer, hashes them into 64 pseudorandom
 *     bytes that are copied back into @ctx->seed.
 *     ->void */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_CSPRNG_reseed(PPQ_CSPRNG* R_ ctx, const void* R_ entropy);
PPQ_API void
PPQ_CSPRNG_reseedFromOS(PPQ_CSPRNG* ctx);
/*=================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_CSPRNG_get ()
 *     Obtain @num_output_bytes pseudorandom bytes and store them at @output.
 *     ->void */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API void
PPQ_CSPRNG_get(
 PPQ_CSPRNG* R_ ctx,
 void* R_       output,            /* Where to write bytes to. */
 uint64_t       num_output_bytes); /* Number pseudorandom bytes to write. */
/*=================================================================================================*/

SSC_END_C_DECLS
#undef R_
#undef AL64_

#endif /* ! */
