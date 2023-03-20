/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef SKC_SKEIN512_H
#define SKC_SKEIN512_H

#include <Base/macros.h>
#include "macros.h"
#include "ubi512.h"

#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

/* Hash @num_bytes_in bytes from @bytes_in,
 * producing a hash output of size @num_bytes_out,
 * storing it at @bytes_out. */
SKC_API void Skc_Skein512_hash(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint64_t       num_bytes_in,
 const uint64_t       num_bytes_out);

/* Hash @num_bytes_in bytes from @bytes_in,
 * producing a hash output of size SKC_THREEFISH512_BLOCK_BYTES,
 * storing it at @bytes_out. */
SKC_API void Skc_Skein512_hash_native(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint64_t       num_bytes_in);

/* Hash @num_bytes_in bytes from @bytes_in along
 * with SKC_THREEFISH512_BLOCK_BYTES bytes of key
 * material from @key_in, producing a message
 * authentication code of size @num_bytes_out,
 * storing it at @bytes_out. */
SKC_API void Skc_Skein512_mac(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint8_t* R_    key_in,
 const uint64_t       num_bytes_in,
 const uint64_t       num_bytes_out);

BASE_END_C_DECLS
#undef R_

#endif /* ! */
