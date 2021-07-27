#ifndef SKC_GRAPH_HASHING_H
#define SKC_GRAPH_HASHING_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <Base/errors.h>
#include <Base/macros.h>
#include "macros.h"
#include "ubi512.h"

#define SKC_GRAPH_HASHING_TEMP_BYTES (SKC_THREEFISH512_BLOCK_BYTES * 2)

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_DECLS
SKC_API void Skc_graph_hash (R_(Skc_UBI512* const) ubi512,
                             R_(uint8_t* const)    temp,
			     R_(uint8_t* const)    graph_memory,
			     const uint8_t         garlic,
			     const uint8_t         lambda);
BASE_END_DECLS
#undef R_

#endif // ~ SKC_GRAPH_HASHING_H
