/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */

#include "Random.h"
#include "Skein512.h"

#define R_ SSC_RESTRICT

uint64_t
PPQ_getRandomNaturalNumber(PPQ_CSPRNG* csprng, uint64_t nat_max)
{
  const uint64_t num_sections = nat_max + 1;
  const uint64_t local_limit = UINT64_MAX - (UINT64_MAX % num_sections); /* local_limit % num_sections == 0 */
  const uint64_t quanta_per_section = local_limit / num_sections;

  /* Initialize a 64-bit word with random data. */
  uint64_t rand_uint64, offset;
  PPQ_storeRandomUint64(csprng, &rand_uint64);
  if (rand_uint64 < local_limit) {
    const uint64_t rounded_down = rand_uint64 - (rand_uint64 % quanta_per_section);
    offset = rounded_down / quanta_per_section;
  } else
    offset = num_sections - 1;
  return offset;
}

uint64_t
PPQ_getRandomUint64WithinRangeInjectEntropy(
 PPQ_CSPRNG*    csprng,
 const uint64_t min_val,
 const uint64_t max_val,
 const char* R_ entropy_cstr)
{
  uint8_t buf [PPQ_THREEFISH512_BLOCK_BYTES];

  SSC_assertMsg(min_val <= max_val, "PPQ_getRandomUint64WithinRangeInjectEntropy: min_val > max_val!\n");

  if (entropy_cstr != SSC_NULL) {
    PPQ_Skein512_hashNative(
     &csprng->ubi512,
     buf,
     (const uint8_t*)entropy_cstr,
     strlen(entropy_cstr)
    );
    PPQ_CSPRNG_reseed(csprng, buf);
    SSC_secureZero(buf, sizeof(buf));
  }
  return min_val + PPQ_getRandomNaturalNumber(csprng, max_val - min_val);
}
