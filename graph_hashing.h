/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
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

#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

SKC_API void Skc_graph_hash(
 Skc_UBI512* const R_ ubi512,
 uint8_t* const R_    temp,
 uint8_t* const R_    graph_memory,
 const uint8_t        garlic,
 const uint8_t        lambda);

BASE_END_C_DECLS
#undef R_

#endif // ~ SKC_GRAPH_HASHING_H
