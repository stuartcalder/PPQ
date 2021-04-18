#include "rand.h"

uint16_t
symm_rand_u16 (Symm_CSPRNG * rng) {
	uint16_t u, c;
	symm_csprng_get( rng, (uint8_t *)&u, sizeof(u) );
	c = u;
	shim_secure_zero( &u, sizeof(u) );
	return c;
}

uint32_t
symm_rand_u32 (Symm_CSPRNG * rng) {
	uint32_t u, c;
	symm_csprng_get( rng, (uint8_t *)&u, sizeof(u) );
	c = u;
	shim_secure_zero( &u, sizeof(u) );
	return c;
}

uint64_t
symm_rand_u64 (Symm_CSPRNG * rng) {
	uint64_t u, c;
	symm_csprng_get( rng, (uint8_t *)&u, sizeof(u) );
	c = u;
	shim_secure_zero( &u, sizeof(u) );
	return c;
}
