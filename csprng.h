#ifndef SYMM_CSPRNG_H
#define SYMM_CSPRNG_H

#include <shim/macros.h>
#include <shim/operations.h>
#include "skein512.h"
#include "macros.h"

typedef struct {
	                    Symm_UBI512 ubi512_ctx;
	SHIM_ALIGNAS (uint64_t) uint8_t buffer [SYMM_THREEFISH512_BLOCK_BYTES * 2];
	SHIM_ALIGNAS (uint64_t) uint8_t seed   [SYMM_THREEFISH512_BLOCK_BYTES];
} Symm_CSPRNG;

SHIM_BEGIN_DECLS

static inline void
symm_csprng_init (Symm_CSPRNG * ctx) {
	shim_obtain_os_entropy( ctx->seed, sizeof(ctx->seed) );
}

SYMM_API void
symm_csprng_reseed (Symm_CSPRNG *   SHIM_RESTRICT ctx,
		    uint8_t const * SHIM_RESTRICT seed);
SYMM_API void
symm_csprng_os_reseed (Symm_CSPRNG * ctx);

SYMM_API void
symm_csprng_get (Symm_CSPRNG * SHIM_RESTRICT ctx,
		 uint8_t *     SHIM_RESTRICT output,
		 uint64_t                    requested_bytes);

SHIM_END_DECLS

#endif // ~ SYMM_CSPRNG_H
