/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#ifndef SKC_SKEIN512_H
#define SKC_SKEIN512_H

#include <Base/macros.h>
#include "macros.h"
#include "ubi512.h"

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_C_DECLS
SKC_API void Skc_Skein512_hash (R_(Skc_UBI512* const) ubi512,
                                uint8_t*              bytes_out,
				const uint8_t*        bytes_in,
				const uint64_t        num_bytes_in,
				const uint64_t        num_bytes_out);
SKC_API void Skc_Skein512_hash_native (R_(Skc_UBI512* const) ubi512,
                                       uint8_t*              bytes_out,
				       const uint8_t*        bytes_in,
				       const uint64_t        num_bytes_in);
SKC_API void Skc_Skein512_mac (R_(Skc_UBI512* const)    ubi512,
                               uint8_t*                 bytes_out,
			       const uint8_t*           bytes_in,
			       R_(const uint8_t*)       key_in,
			       const uint64_t           num_bytes_in,
			       const uint64_t           num_bytes_out);
BASE_END_C_DECLS
#undef R_

#endif /* ! */
