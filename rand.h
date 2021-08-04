#ifndef SKC_RAND_H
#define SKC_RAND_H

#include "csprng.h"
#include "macros.h"

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_DECLS

BASE_INLINE void Skc_rand_uint16 (Skc_CSPRNG* csprng, uint16_t* buffer) {
	Skc_CSPRNG_get(csprng, (uint8_t*)buffer, sizeof(*buffer));
}
BASE_INLINE void Skc_rand_uint32 (Skc_CSPRNG* csprng, uint32_t* buffer) {
	Skc_CSPRNG_get(csprng, (uint8_t*)buffer, sizeof(*buffer));
}
BASE_INLINE void Skc_rand_uint64 (Skc_CSPRNG* csprng, uint64_t* buffer) {
	Skc_CSPRNG_get(csprng, (uint8_t*)buffer, sizeof(*buffer));
}
SKC_API uint64_t Skc_rand_nat_num (Skc_CSPRNG* csprng, uint64_t nat_max);

BASE_END_DECLS
#undef R_

#endif /* ~ ifndef SKC_RAND_H */
