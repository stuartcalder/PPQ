/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_GRAPHHASH_H
#define PPQ_GRAPHHASH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <SSC/Macro.h>
#include <SSC/Error.h>

#include "Macro.h"
#include "Ubi512.h"

#define PPQ_GRAPHHASH_TEMP_BYTES (PPQ_THREEFISH512_BLOCK_BYTES * 2)

#define R_ PPQ_RESTRICT
PPQ_BEGIN_C_DECLS

PPQ_API void
PPQ_graphHash(
 PPQ_UBI512* const R_ ubi512,
 uint8_t* const R_    temp,
 uint8_t* const R_    graph_memory,
 const uint8_t        garlic,
 const uint8_t        lambda);

PPQ_END_C_DECLS
#undef R_

#endif // ~ PPQ_GRAPHHASH_H
