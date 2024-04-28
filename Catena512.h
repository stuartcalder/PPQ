/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_CATENA512_H
#define PPQ_CATENA512_H

#include <SSC/Error.h>
#include <SSC/Macro.h>
#include <SSC/Operation.h>

#include "Macro.h"
#include "GraphHash.h"
#include "Ubi512.h"

#define PPQ_CATENA512_SALT_BITS          256
#define PPQ_CATENA512_SALT_BYTES         32
#define PPQ_CATENA512_MAX_PASSWORD_BYTES 125
#define PPQ_CATENA512_TWEAK_BYTES        (PPQ_THREEFISH512_BLOCK_BYTES + 1 + 1 + 2 + 2)
#define PPQ_CATENA512_RNG_BYTES          PPQ_THREEFISH512_BLOCK_BYTES
#define PPQ_CATENA512_DOMAIN_PWSCRAMBLER UINT8_C(0)
#define PPQ_CATENA512_DOMAIN_KDF         UINT8_C(1)
#define PPQ_CATENA512_DOMAIN_POW         UINT8_C(2)
#define PPQ_CATENA512_MHF_TEMP_BYTES     PPQ_GRAPHHASH_TEMP_BYTES

#define AL64_ SSC_ALIGNAS(uint64_t)
#define R_    SSC_RESTRICT
SSC_BEGIN_C_DECLS

enum {
  PPQ_CATENA512_SUCCESS = 0,
  PPQ_CATENA512_ALLOC_FAILURE = -1
};

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Catena512 {}
 *     Memory-Hard password hashing. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_UBI512    ubi512;
  uint8_t*      graph_memory;
  AL64_ uint8_t x    [PPQ_THREEFISH512_BLOCK_BYTES];
  AL64_ uint8_t salt [PPQ_CATENA512_SALT_BYTES];
  union {
    uint8_t tw_pw_salt [PPQ_CATENA512_TWEAK_BYTES + PPQ_CATENA512_MAX_PASSWORD_BYTES + PPQ_CATENA512_SALT_BYTES];
    uint8_t flap       [PPQ_THREEFISH512_BLOCK_BYTES * 3];
    uint8_t catena     [PPQ_THREEFISH512_BLOCK_BYTES + 1];
    uint8_t phi        [PPQ_THREEFISH512_BLOCK_BYTES * 2];
    uint8_t mhf        [PPQ_CATENA512_MHF_TEMP_BYTES];
    struct {
      uint8_t word_buf [PPQ_THREEFISH512_BLOCK_BYTES * 2];
      uint8_t rng      [PPQ_CATENA512_RNG_BYTES];
    } gamma;
  } temp;
} PPQ_Catena512;
#define PPQ_CATENA512_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Catena512, 0)
PPQ_INLINE void
PPQ_Catena512_init(PPQ_Catena512* ctx)
{
  PPQ_UBI512_init(&ctx->ubi512);
}
/*===============================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Catena512_noPhi () */
/*     Memory-Hard password hashing where the ``Phi`` function IS NOT USED.
 *         @output: Write 64 output bytes here.
 *         @password: Read input password bytes from here.
 *         @password_size: The number of input password bytes to read.
 *         @g_low:  ``garlic low``  -- The lower memory bound.
 *         @g_high: ``garlic high`` -- The upper memory bound.
 *         @lambda: The iteration count.
 *         ->SSC_Error_t: Zero indicates success; nonzero indicates memory allocation failure. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API SSC_Error_t
PPQ_Catena512_noPhi(
 PPQ_Catena512* R_ ctx,
 uint8_t* R_       output,
 const uint8_t* R_ password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda);
/*===============================================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* PPQ_Catena512_usePhi () */
/*     Memory-Hard password hashing where the ``Phi`` function IS USED.
 *         @output: Write 64 output bytes here.
 *         @password: Read input password bytes from here.
 *         @password_size: The number of input password bytes to read.
 *         @g_low:  ``garlic low``  -- The lower memory bound.
 *         @g_high: ``garlic high`` -- The upper memory bound.
 *         ->SSC_Error_t: Zero indicates success; nonzero indicates memory allocation failure. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
PPQ_API SSC_Error_t
PPQ_Catena512_usePhi(
 PPQ_Catena512* R_ ctx,
 uint8_t* R_       output,
 const uint8_t* R_ password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda);
/*===============================================================================================================*/

SSC_END_C_DECLS
#undef R_
#undef AL64_
#endif // ~ PPQ_CATENA512_H
