#ifndef SYMM_GRAPH_HASHING_H
#define SYMM_GRAPH_HASHING_H

#include <shim/macros.h>
#include <shim/errors.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ubi512.h"
#include "macros.h"

#define SYMM_GRAPH_HASHING_TEMP_BYTES (SYMM_THREEFISH512_BLOCK_BYTES * 2)

SHIM_BEGIN_DECLS

SYMM_API void
symm_graph_hash (Symm_UBI512 * SHIM_RESTRICT ubi512_ctx,
		 uint8_t *     SHIM_RESTRICT temp,
		 uint8_t *     SHIM_RESTRICT graph_memory,
		 uint8_t const               garlic,
		 uint8_t const               lambda);

SHIM_END_DECLS

#endif // ~ SYMM_GRAPH_HASHING_H
