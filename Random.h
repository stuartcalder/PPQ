/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_RANDOM_H
#define PPQ_RANDOM_H

#include "Macro.h"
#include "CSPRNG.h"

#define R_ SSC_RESTRICT
#define IMPL_ { PPQ_CSPRNG_get(csprng, buffer, sizeof(*buffer)); }
SSC_BEGIN_C_DECLS

/* Store a pseudorandom uint16_t at @buffer. */
PPQ_INLINE void
PPQ_storeRandomUint16(PPQ_CSPRNG* csprng, uint16_t* buffer)
IMPL_

/* Store a pseudorandom uint32_t at @buffer. */
PPQ_INLINE void
PPQ_storeRandomUint32(PPQ_CSPRNG* csprng, uint32_t* buffer)
IMPL_

/* Store a pseudorandom uint64_t at @buffer. */
PPQ_INLINE void
PPQ_storeRandomUint64(PPQ_CSPRNG* csprng, uint64_t* buffer)
IMPL_

/* Store a pseudorandom natural number at most @nat_max. */
PPQ_API uint64_t
PPQ_getRandomNaturalNumber(PPQ_CSPRNG* csprng, uint64_t nat_max);

/* Generate a pseudorandom uint64_t from withing a range, and supplement the @csprng. */
PPQ_API uint64_t
PPQ_getRandomUint64WithinRangeInjectEntropy(
 PPQ_CSPRNG*    csprng,
 const uint64_t min_val, /* Generate a natural number at minimum @min_val. */
 const uint64_t max_val, /* Generate a natural number at most @max_val. */
 const char* R_ entropy_cstr); /* Supplement @csprng using the entropy of @entropy_cstr. */

/* Generate a pseudorandom uint64_t within a range. */
PPQ_INLINE uint64_t
PPQ_getRandomUint64WithinRange(
 PPQ_CSPRNG*    csprng,
 const uint64_t min_val, /* Generate a natural number at minimum @min_val. */
 const uint64_t max_val) /* Generate a natural number at most @max_val. */
{
  return PPQ_getRandomUint64WithinRangeInjectEntropy(csprng, min_val, max_val, SSC_NULL);
}

PPQ_INLINE uint64_t
PPQ_getRandomNaturalNumberInjectEntropy(
 PPQ_CSPRNG*    csprng,
 const uint64_t nat_max,
 const char* R_ entropy_cstr)
{
  return PPQ_getRandomUint64WithinRangeInjectEntropy(csprng, 0, nat_max, entropy_cstr);
}

SSC_END_C_DECLS
#undef IMPL_
#undef R_

#endif /* ~ ifndef PPQ_RANDOM_H */
