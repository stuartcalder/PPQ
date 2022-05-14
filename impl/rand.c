/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#include "rand.h"

uint64_t Skc_rand_nat_num (Skc_CSPRNG* csprng, uint64_t nat_max) {
	const uint64_t num_sections = nat_max + 1;
	const uint64_t local_limit = UINT64_MAX - (UINT64_MAX % num_sections); /* local_limit % num_sections == 0 */
	const uint64_t quanta_per_section = local_limit / num_sections;

	/* Initialize a 64-bit word with random data. */
	uint64_t rand_uint64, offset;
	Skc_rand_uint64(csprng, &rand_uint64);
	if (rand_uint64 < local_limit) {
		const uint64_t rounded_down = rand_uint64 - (rand_uint64 % quanta_per_section);
		offset = rounded_down / quanta_per_section;
	} else
		offset = num_sections - 1;
	return offset;
}
