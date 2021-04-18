#ifndef SYMM_RAND_H
#define SYMM_RAND_H

#include "macros.h"
#include "csprng.h"

SHIM_BEGIN_DECLS

#define SYMM_RAND_U_(bits) \
	SYMM_API uint##bits##_t \
	symm_rand_u##bits (Symm_CSPRNG *)
SYMM_RAND_U_(16);
SYMM_RAND_U_(32);
SYMM_RAND_U_(64);

SHIM_END_DECLS


#undef SYMM_RAND_U_
#endif /* ~ ifndef SYMM_RAND_H */
