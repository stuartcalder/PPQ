/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#include "rand.h"
#include "skein512.h"
#define R_(Ptr) Ptr BASE_RESTRICT

uint64_t Skc_rand_nat_num(Skc_CSPRNG* csprng, uint64_t nat_max)
{
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

uint64_t Skc_rand_range_entropy(Skc_CSPRNG* csprng, const uint64_t min_val, const uint64_t max_val, R_(const char*) entropy_cstr)
{
  uint8_t buf[SKC_THREEFISH512_BLOCK_BYTES];

  Base_assert_msg(min_val <= max_val, "Skc_rand_range_entropy: min_val > max_val!\n");

  if (entropy_cstr != BASE_NULL) {
    Skc_Skein512_hash_native(
     &csprng->ubi512,
     buf,
     entropy_cstr,
     strlen(entropy_cstr)
    );
    Skc_CSPRNG_reseed(csprng, buf);
    Base_secure_zero(buf, sizeof(buf));
  }
  return min_val + Skc_rand_nat_num(csprng, max_val - min_val);
}
