/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#ifndef SKC_RAND_H
#define SKC_RAND_H

#include "csprng.h"
#include "macros.h"

#define R_ BASE_RESTRICT
#define IMPL_ { Skc_CSPRNG_get(csprng, buffer, sizeof(*buffer)); }
BASE_BEGIN_C_DECLS

/* Store a pseudorandom uint16_t at @buffer. */
BASE_INLINE void Skc_rand_uint16(Skc_CSPRNG* csprng, uint16_t* buffer) IMPL_

/* Store a pseudorandom uint32_t at @buffer. */
BASE_INLINE void Skc_rand_uint32(Skc_CSPRNG* csprng, uint32_t* buffer) IMPL_

/* Store a pseudorandom uint64_t at @buffer. */
BASE_INLINE void Skc_rand_uint64(Skc_CSPRNG* csprng, uint64_t* buffer) IMPL_

/* Store a pseudorandom natural number at most @nat_max. */
SKC_API uint64_t Skc_rand_nat_num(Skc_CSPRNG* csprng, uint64_t nat_max);

/* Generate a pseudorandom uint64_t from withing a range, and supplement the @csprng. */
SKC_API uint64_t Skc_rand_range_entropy(
 Skc_CSPRNG*    csprng,
 const uint64_t min_val, /* Generate a natural number at minimum @min_val. */
 const uint64_t max_val, /* Generate a natural number at most @max_val. */
 const char* R_ entropy_cstr); /* Supplement @csprng using the entropy of @entropy_cstr. */

/* Generate a pseudorandom uint64_t within a range. */
BASE_INLINE uint64_t Skc_rand_range(
 Skc_CSPRNG*    csprng,
 const uint64_t min_val, /* Generate a natural number at minimum @min_val. */
 const uint64_t max_val) /* Generate a natural number at most @max_val. */
{
  return Skc_rand_range_entropy(csprng, min_val, max_val, BASE_NULL);
}

BASE_END_C_DECLS
#undef IMPL_
#undef R_

#endif /* ~ ifndef SKC_RAND_H */
