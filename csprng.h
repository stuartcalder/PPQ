/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef SKC_CSPRNG_H
#define SKC_CSPRNG_H

#include <Base/macros.h>
#include <Base/operations.h>
#include "macros.h"
#include "ubi512.h"
#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

typedef struct {
  Skc_UBI512                     ubi512;
  BASE_ALIGNAS(uint64_t) uint8_t buffer [SKC_THREEFISH512_BLOCK_BYTES * 2];
  BASE_ALIGNAS(uint64_t) uint8_t seed   [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_CSPRNG;
#define SKC_CSPRNG_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_CSPRNG, SKC_UBI512_NULL_LITERAL, {0}, {0})

/* Obtain entropy from the OS, and use it as a seed for the RNG.
 * No return value; could possibly fail fatally. */
SKC_INLINE void
Skc_CSPRNG_init(Skc_CSPRNG* ctx)
{
  Skc_UBI512_init(&ctx->ubi512);
  Base_get_os_entropy(ctx->seed, sizeof(ctx->seed));
}

/* Securely zero over the RNG data.
 * No return value; cannot fail. */
SKC_INLINE void
Skc_CSPRNG_del(Skc_CSPRNG* ctx)
{
  Base_secure_zero(ctx, sizeof(*ctx));
}

/* Re-seed using supplied entropy.
 * No return value; cannot fail. */
SKC_API void
Skc_CSPRNG_reseed(
 Skc_CSPRNG* R_ ctx,
 const void* R_ entropy); /* 64 bytes of pseudorandom data to read and hash. */

/* Re-seed, using entropy supplied by the OS.
 * No return value; could possibly fail fatally. */
SKC_API void
Skc_CSPRNG_os_reseed(Skc_CSPRNG* ctx);

SKC_API void
Skc_CSPRNG_get(
 Skc_CSPRNG* R_ ctx,
 void* R_       output,            /* Where to write bytes to. */
 uint64_t       num_output_bytes); /* Number pseudorandom bytes to write. */
/* Write pseudorandom bytes.
 * No return value; cannot fail. */

BASE_END_C_DECLS
#undef R_

#endif /* ! */
