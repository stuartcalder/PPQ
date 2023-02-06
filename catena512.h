/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#ifndef SKC_CATENA512_H
#define SKC_CATENA512_H

#include <Base/errors.h>
#include <Base/macros.h>
#include <Base/operations.h>
#include "graph_hashing.h"
#include "macros.h"
#include "ubi512.h"

#define SKC_CATENA512_SALT_BITS			256
#define SKC_CATENA512_SALT_BYTES		32
#define SKC_CATENA512_MAX_PASSWORD_BYTES	120
#define SKC_CATENA512_TWEAK_BYTES		(SKC_THREEFISH512_BLOCK_BYTES + 1 + 1 + 2 + 2)
#define SKC_CATENA512_RNG_BYTES			SKC_THREEFISH512_BLOCK_BYTES
#define SKC_CATENA512_DOMAIN_PWSCRAMBLER	UINT8_C(0)
#define SKC_CATENA512_DOMAIN_KDF		UINT8_C(1)
#define SKC_CATENA512_DOMAIN_POW		UINT8_C(2)
#define SKC_CATENA512_MHF_TEMP_BYTES		SKC_GRAPH_HASHING_TEMP_BYTES
#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

enum {
  SKC_CATENA512_SUCCESS = 0,
  SKC_CATENA512_ALLOC_FAILURE = 1
};

typedef struct {
  Skc_UBI512	                 ubi512;
  uint8_t*	                 graph_memory;
  BASE_ALIGNAS(uint64_t) uint8_t x    [SKC_THREEFISH512_BLOCK_BYTES];
  BASE_ALIGNAS(uint64_t) uint8_t salt [SKC_CATENA512_SALT_BYTES];
  union {
    uint8_t tw_pw_salt [SKC_CATENA512_TWEAK_BYTES + SKC_CATENA512_MAX_PASSWORD_BYTES + SKC_CATENA512_SALT_BYTES];
    uint8_t flap       [SKC_THREEFISH512_BLOCK_BYTES * 3];
    uint8_t catena     [SKC_THREEFISH512_BLOCK_BYTES + 1];
    uint8_t phi        [SKC_THREEFISH512_BLOCK_BYTES * 2];
    uint8_t mhf        [SKC_CATENA512_MHF_TEMP_BYTES];
    struct {
      uint8_t word_buf [SKC_THREEFISH512_BLOCK_BYTES * 2];
      uint8_t rng      [SKC_CATENA512_RNG_BYTES];
    } gamma;
  } temp;
} Skc_Catena512;
#define SKC_CATENA512_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Catena512, 0)

BASE_INLINE void Skc_Catena512_init(Skc_Catena512* ctx)
/* TODO */
{
  Skc_UBI512_init(&ctx->ubi512);
}

SKC_API int Skc_Catena512_without_phi(
 Skc_Catena512* R_ ctx,
 uint8_t* R_       output,
 uint8_t* R_       password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda);
/* TODO */

SKC_API int Skc_Catena512_with_phi(
 Skc_Catena512* R_ ctx,
 uint8_t* R_       output,
 uint8_t* R_       password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda);
/* TODO */

BASE_END_C_DECLS
#undef R_
#endif // ~ SKC_CATENA512_H
