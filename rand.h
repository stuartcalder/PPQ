/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#ifndef SKC_RAND_H
#define SKC_RAND_H

#include "csprng.h"
#include "macros.h"

#define R_(ptr) ptr BASE_RESTRICT
#define RAND_(bits) \
  BASE_INLINE void Skc_rand_uint##bits (Skc_CSPRNG* csprng, uint##bits##_t* buffer) { \
    Skc_CSPRNG_get(csprng, (uint8_t*)buffer, sizeof(*buffer)); \
  }
BASE_BEGIN_C_DECLS
RAND_(16)
RAND_(32)
RAND_(64)
SKC_API uint64_t Skc_rand_nat_num (Skc_CSPRNG* csprng, uint64_t nat_max);
BASE_END_C_DECLS
#undef RAND_
#undef R_

#endif /* ~ ifndef SKC_RAND_H */
