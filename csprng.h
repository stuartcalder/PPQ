#ifndef SYMM_CSPRNG_H
#define SYMM_CSPRNG_H

#include "macros.h"
#include "skein512.h"
#include <shim/macros.h>
#include <shim/operations.h>

#define WORD_ALIGN_ SHIM_ALIGNAS (uint64_t)
typedef struct {
	Symm_UBI512	    ubi512_ctx;
	WORD_ALIGN_ uint8_t buffer [SYMM_THREEFISH512_BLOCK_BYTES * 2];
	WORD_ALIGN_ uint8_t seed   [SYMM_THREEFISH512_BLOCK_BYTES];
} Symm_CSPRNG;
#undef WORD_ALIGN_

SHIM_BEGIN_DECLS

static inline void
symm_csprng_init (Symm_CSPRNG * ctx) {
	shim_obtain_os_entropy( ctx->seed, sizeof(ctx->seed) );
}

static inline void
symm_csprng_delete (Symm_CSPRNG * ctx) {
	shim_secure_zero( ctx, sizeof(*ctx) );
}

SYMM_API void
symm_csprng_reseed (Symm_CSPRNG *   SHIM_RESTRICT ctx,
		    uint8_t const * SHIM_RESTRICT seed);
SYMM_API void
symm_csprng_os_reseed (Symm_CSPRNG * ctx);

SYMM_API void
symm_csprng_get (Symm_CSPRNG * SHIM_RESTRICT ctx,
		 uint8_t *     SHIM_RESTRICT output,
		 int64_t                     requested_bytes);

SHIM_END_DECLS

#endif // ~ SYMM_CSPRNG_H
