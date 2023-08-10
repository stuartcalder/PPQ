/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_SKEIN512_H
#define PPQ_SKEIN512_H

#include <SSC/Macro.h>

#include "Macro.h"
#include "Ubi512.h"

#define R_ SSC_RESTRICT
SSC_BEGIN_C_DECLS

/* Hash @num_bytes_in bytes from @bytes_in,
 * producing a hash output of size @num_bytes_out,
 * storing it at @bytes_out. */
PPQ_API void
PPQ_Skein512_hash(
 PPQ_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint64_t       num_bytes_in,
 const uint64_t       num_bytes_out);

/* Hash @num_bytes_in bytes from @bytes_in,
 * producing a hash output of size PPQ_THREEFISH512_BLOCK_BYTES,
 * storing it at @bytes_out. */
PPQ_API void
PPQ_Skein512_hashNative(
 PPQ_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint64_t       num_bytes_in);

/* Hash @num_bytes_in bytes from @bytes_in along
 * with PPQ_THREEFISH512_BLOCK_BYTES bytes of key
 * material from @key_in, producing a message
 * authentication code of size @num_bytes_out,
 * storing it at @bytes_out. */
PPQ_API void
PPQ_Skein512_mac(
 PPQ_UBI512* const R_ ubi512,
 uint8_t*             bytes_out,
 const uint8_t*       bytes_in,
 const uint8_t* R_    key_in,
 const uint64_t       num_bytes_in,
 const uint64_t       num_bytes_out);

SSC_END_C_DECLS
#undef R_

#endif /* ! */
