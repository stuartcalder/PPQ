#ifndef SKC_RAND_H
#define SKC_RAND_H

#include "csprng.h"
#include "macros.h"

BASE_BEGIN_DECLS
SKC_API uint16_t Skc_rand_u16 (Skc_CSPRNG*);
SKC_API uint32_t Skc_rand_u32 (Skc_CSPRNG*);
SKC_API uint64_t Skc_rand_u64 (Skc_CSPRNG*);
BASE_END_DECLS

#endif /* ~ ifndef SKC_RAND_H */
