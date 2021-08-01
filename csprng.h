#ifndef SKC_CSPRNG_H
#define SKC_CSPRNG_H

#include <Base/macros.h>
#include <Base/operations.h>
#include "macros.h"
#include "skein512.h"

#define ALIGN_ BASE_ALIGNAS(uint64_t)
typedef struct {
	Skc_UBI512     ubi512;
	ALIGN_ uint8_t buffer [SKC_THREEFISH512_BLOCK_BYTES * 2];
	ALIGN_ uint8_t seed   [SKC_THREEFISH512_BLOCK_BYTES];
} Skc_CSPRNG;
#undef ALIGN_

#define SKC_CSPRNG_NULL_LITERAL (Skc_CSPRNG){0}

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_DECLS
BASE_INLINE void Skc_CSPRNG_init (Skc_CSPRNG* ctx) {
	Base_get_os_entropy(ctx->seed, sizeof(ctx->seed));
}
BASE_INLINE void Skc_CSPRNG_del (Skc_CSPRNG* ctx) {
	Base_secure_zero(ctx, sizeof(*ctx));
}
SKC_API void Skc_CSPRNG_reseed    (R_(Skc_CSPRNG*) ctx, R_(const uint8_t*) seed);
SKC_API void Skc_CSPRNG_os_reseed (Skc_CSPRNG* ctx);
SKC_API void Skc_CSPRNG_get       (R_(Skc_CSPRNG*) ctx, R_(uint8_t*) output, uint64_t requested_bytes);
BASE_END_DECLS
#undef R_

#endif /* ! */
