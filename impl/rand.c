#include "rand.h"

uint16_t Skc_rand_u16 (Skc_CSPRNG* rng) {
	uint16_t u, c;
	Skc_CSPRNG_get(rng, (uint8_t*)&u, sizeof(u));
	c = u;
	Base_secure_zero(&u, sizeof(u));
	return c;
}
uint32_t Skc_rand_u32 (Skc_CSPRNG* rng) {
	uint32_t u, c;
	Skc_CSPRNG_get(rng, (uint8_t*)&u, sizeof(u));
	c = u;
	Base_secure_zero(&u, sizeof(u));
	return c;
}
uint64_t Skc_rand_u64 (Skc_CSPRNG* rng) {
	uint64_t u, c;
	Skc_CSPRNG_get(rng, (uint8_t*)&u, sizeof(u));
	c = u;
	Base_secure_zero(&u, sizeof(u));
	return c;
}
