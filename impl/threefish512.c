/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include <Base/mem.h>
#include "threefish512.h"
#include <stdint.h>

#define R_ BASE_RESTRICT
typedef Skc_Threefish512_Static  Static_t;
typedef Skc_Threefish512_Dynamic Dynamic_t;
typedef Skc_Threefish512_CTR     Ctr_t;

#if   BASE_ENDIAN == BASE_ENDIAN_LITTLE
 #define LOAD64_(Word64)  Word64
 #define STORE64_(Word64) Word64
#elif BASE_ENDIAN == BASE_ENDIAN_BIG
 #define LOAD64_(Word64)  Base_swap_64(Word64)
 #define STORE64_(Word64) Base_swap_64(Word64)
#else
 #error "Bad endian."
#endif

#define LOAD_WORD_(Key, Subkey, I) LOAD64_(Key[((Subkey) + I) % SKC_THREEFISH512_EXTERNAL_KEY_WORDS])

#define STORE_WORD_(Subkey, I, Add) \
 ctx->key_schedule[((Subkey) * SKC_THREEFISH512_BLOCK_WORDS) + I] = STORE64_(LOAD_WORD_(key, (Subkey), I) + Add)

#define MAKE_SUBKEY_(Subkey) \
 STORE_WORD_(Subkey, 0, UINT64_C(0));\
 STORE_WORD_(Subkey, 1, UINT64_C(0));\
 STORE_WORD_(Subkey, 2, UINT64_C(0));\
 STORE_WORD_(Subkey, 3, UINT64_C(0));\
 STORE_WORD_(Subkey, 4, UINT64_C(0));\
 STORE_WORD_(Subkey, 5, LOAD64_(twk[(Subkey) % 3]));\
 STORE_WORD_(Subkey, 6, LOAD64_(twk[((Subkey) + 1) % 3]));\
 STORE_WORD_(Subkey, 7, (Subkey))
#define MAKE_4_SUBKEYS_(Start_Subkey) do {\
 MAKE_SUBKEY_(Start_Subkey + 0);\
 MAKE_SUBKEY_(Start_Subkey + 1);\
 MAKE_SUBKEY_(Start_Subkey + 2);\
 MAKE_SUBKEY_(Start_Subkey + 3);\
} while (0)

void Skc_Threefish512_Static_init(
 Static_t* const R_ ctx,
 uint64_t* const R_ key,
 uint64_t* const R_ twk)
{
  Skc_Threefish512_calc_ks_parity_words(key, twk);
  MAKE_4_SUBKEYS_(0);
  MAKE_4_SUBKEYS_(4);
  MAKE_4_SUBKEYS_(8);
  MAKE_4_SUBKEYS_(12);
  MAKE_SUBKEY_(16);
  MAKE_SUBKEY_(17);
  MAKE_SUBKEY_(18);
}

#define DO_MIX_(Idx, Rot_Const) do {\
  uint64_t w0, w1;\
  w0 = LOAD64_(ctx->state[(Idx) * 2]);\
  w1 = LOAD64_(ctx->state[((Idx) * 2) + 1]);\
  w0 += w1;\
  ctx->state[(Idx) * 2] = STORE64_(w0);\
  ctx->state[((Idx) * 2) + 1] = STORE64_(Base_rotl_64(w1, Rot_Const) ^ w0);\
} while (0)

/* Rounds 0-3 use subkey idx 0, 4-7 use subkey idx 1, etc. */
#define SUBKEY_INDEX_(Round) ((Round) / 4)
#define SKI_(Rnd) SUBKEY_INDEX_(Rnd)
/* What is the offset of this round's subkey? */
#define SUBKEY_OFFSET_(Round) (SKI_(Round) * SKC_THREEFISH512_BLOCK_WORDS)
#define SKO_(Rnd) SUBKEY_OFFSET_(Rnd)

#define USE_SUBKEY_(Op, Rnd) do {\
  uint64_t st, ks;\
  st = LOAD64_(ctx->state[0]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 0]);\
  ctx->state[0] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[1]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 1]);\
  ctx->state[1] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[2]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 2]);\
  ctx->state[2] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[3]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 3]);\
  ctx->state[3] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[4]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 4]);\
  ctx->state[4] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[5]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 5]);\
  ctx->state[5] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[6]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 6]);\
  ctx->state[6] = STORE64_(st Op ks);\
  st = LOAD64_(ctx->state[7]);\
  ks = LOAD64_(ctx->key_schedule[SKO_(Rnd) + 7]);\
  ctx->state[7] = STORE64_(st Op ks);\
} while (0)

#define ADD_SUBKEY_(Rnd)      USE_SUBKEY_(+, Rnd)
#define SUBTRACT_SUBKEY_(Rnd) USE_SUBKEY_(-, Rnd)
#define PERMUTE_ do {\
  uint64_t w0, w1;\
  w0 = ctx->state[6];\
  ctx->state[6] = ctx->state[0];\
  w1 = ctx->state[4];\
  ctx->state[4] = w0;\
  w0 = ctx->state[2];\
  ctx->state[2] = w1;\
  ctx->state[0] = w0;\
  w0 = ctx->state[3];\
  ctx->state[3] = ctx->state[7];\
  ctx->state[7] = w0;\
} while (0)

#define MIX4_PERM_(Rc0, Rc1, Rc2, Rc3)\
 DO_MIX_(0, Rc0); DO_MIX_(1, Rc1);\
 DO_MIX_(2, Rc2); DO_MIX_(3, Rc3);\
 PERMUTE_

#define ENC_ROUND_(Rnd_Start, Rc0_0, Rc0_1, Rc0_2, Rc0_3,\
                              Rc1_0, Rc1_1, Rc1_2, Rc1_3,\
			      Rc2_0, Rc2_1, Rc2_2, Rc2_3,\
			      Rc3_0, Rc3_1, Rc3_2, Rc3_3)\
 ADD_SUBKEY_(Rnd_Start);\
 MIX4_PERM_(Rc0_0, Rc0_1, Rc0_2, Rc0_3);\
 MIX4_PERM_(Rc1_0, Rc1_1, Rc1_2, Rc1_3);\
 MIX4_PERM_(Rc2_0, Rc2_1, Rc2_2, Rc2_3);\
 MIX4_PERM_(Rc3_0, Rc3_1, Rc3_2, Rc3_3)

#define ENC_ROUND_PHASE_0_(Rnd_Start) ENC_ROUND_(Rnd_Start, 46, 36, 19, 37,\
                                                            33, 27, 14, 42,\
							    17, 49, 36, 39,\
							    44,  9, 54, 56)

#define ENC_ROUND_PHASE_1_(Rnd_Start) ENC_ROUND_(Rnd_Start, 39, 30, 34, 24,\
                                                            13, 50, 10, 17,\
							    25, 29, 39, 43,\
							     8, 35, 56, 22)
void Skc_Threefish512_Static_encipher(
 Static_t* const R_ ctx,
 void* const        v_ctext,
 const void* const  v_ptext)
{
  uint8_t* const       ctext = (uint8_t*)      v_ctext;
  const uint8_t* const ptext = (const uint8_t*)v_ptext;
  BASE_STATIC_ASSERT(sizeof(ctx->state) == SKC_THREEFISH512_BLOCK_BYTES, "State is one threefish512 block.");
  memcpy(ctx->state, ptext, sizeof(ctx->state));
  ENC_ROUND_PHASE_0_(0);
  ENC_ROUND_PHASE_1_(4);
  ENC_ROUND_PHASE_0_(8);
  ENC_ROUND_PHASE_1_(12);
  ENC_ROUND_PHASE_0_(16);
  ENC_ROUND_PHASE_1_(20);
  ENC_ROUND_PHASE_0_(24);
  ENC_ROUND_PHASE_1_(28);
  ENC_ROUND_PHASE_0_(32);
  ENC_ROUND_PHASE_1_(36);
  ENC_ROUND_PHASE_0_(40);
  ENC_ROUND_PHASE_1_(44);
  ENC_ROUND_PHASE_0_(48);
  ENC_ROUND_PHASE_1_(52);
  ENC_ROUND_PHASE_0_(56);
  ENC_ROUND_PHASE_1_(60);
  ENC_ROUND_PHASE_0_(64);
  ENC_ROUND_PHASE_1_(68);
  ADD_SUBKEY_(72);
  memcpy(ctext, ctx->state, sizeof(ctx->state));
}

#undef USE_SUBKEY_
#define USE_SUBKEY_(Op, Rnd) do {\
  uint64_t st, ek, et;\
  st = LOAD64_(ctx->state[0]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 0);\
  ctx->state[0] = STORE64_(st Op ek);\
  st = LOAD64_(ctx->state[1]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 1);\
  ctx->state[1] = STORE64_(st Op ek);\
  st = LOAD64_(ctx->state[2]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 2);\
  ctx->state[2] = STORE64_(st Op ek);\
  st = LOAD64_(ctx->state[3]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 3);\
  ctx->state[3] = STORE64_(st Op ek);\
  st = LOAD64_(ctx->state[4]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 4);\
  ctx->state[4] = STORE64_(st Op ek);\
  st = LOAD64_(ctx->state[5]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 5);\
  et = LOAD64_(ctx->extern_tweak[SKI_(Rnd) % 3]);\
  ctx->state[5] = STORE64_(st Op (ek + et));\
  st = LOAD64_(ctx->state[6]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 6);\
  et = LOAD64_(ctx->extern_tweak[(SKI_(Rnd) + 1) % 3]);\
  ctx->state[6] = STORE64_(st Op (ek + et));\
  st = LOAD64_(ctx->state[7]);\
  ek = LOAD_WORD_(ctx->extern_key, SKI_(Rnd), 7);\
  et = SKI_(Rnd);\
  ctx->state[7] = STORE64_(st Op (ek + et));\
} while (0)

void Skc_Threefish512_Dynamic_encipher(
 Dynamic_t* const R_ ctx,
 void* const         v_ctext,
 const void* const   v_ptext)
{
  uint8_t* const       ctext = (uint8_t*)      v_ctext;
  const uint8_t* const ptext = (const uint8_t*)v_ptext;
  memcpy(ctx->state, ptext, sizeof(ctx->state));
  ENC_ROUND_PHASE_0_(0);
  ENC_ROUND_PHASE_1_(4);
  ENC_ROUND_PHASE_0_(8);
  ENC_ROUND_PHASE_1_(12);
  ENC_ROUND_PHASE_0_(16);
  ENC_ROUND_PHASE_1_(20);
  ENC_ROUND_PHASE_0_(24);
  ENC_ROUND_PHASE_1_(28);
  ENC_ROUND_PHASE_0_(32);
  ENC_ROUND_PHASE_1_(36);
  ENC_ROUND_PHASE_0_(40);
  ENC_ROUND_PHASE_1_(44);
  ENC_ROUND_PHASE_0_(48);
  ENC_ROUND_PHASE_1_(52);
  ENC_ROUND_PHASE_0_(56);
  ENC_ROUND_PHASE_1_(60);
  ENC_ROUND_PHASE_0_(64);
  ENC_ROUND_PHASE_1_(68);
  ADD_SUBKEY_(72);
  memcpy(ctext, ctx->state, sizeof(ctx->state));
}

void Skc_Threefish512_CTR_init(Ctr_t* const R_ ctx, const void* const R_ init_vec)
{ 
  uint8_t* p = ctx->keystream + 8;
  /* Zero byte indices 8 through 23 inclusive. */
  memset(p, 0, (SKC_THREEFISH512_CTR_IV_BYTES - 8));
  /* Copy 32 pseudorandom @init_vec bytes into the last
   * 32 bytes of the keystream. */
  p = ctx->keystream + SKC_THREEFISH512_CTR_IV_BYTES;
  memcpy(p, init_vec, SKC_THREEFISH512_CTR_IV_BYTES);
  /* The first 8 bytes of the keystream are the counter.
   * At this point the counter is uninitialized, and will
   * be initialized during Skc_Threefish512_CTR_xor_keystream(). */
}

#define INC_U64_(U64p) do {\
  uint64_t tmp;\
  memcpy(&tmp, U64p, sizeof(tmp));\
  tmp = STORE64_(LOAD64_(tmp) + 1);\
  memcpy(U64p, &tmp, sizeof(tmp));\
} while(0)

void Skc_Threefish512_CTR_xor_keystream(
 Ctr_t* const R_ ctx,
 void*           v_output,
 const void*     v_input,
 uint64_t        input_size,
 uint64_t        start_byte)
{
  uint8_t*       output = (uint8_t*)      v_output;
  const uint8_t* input  = (const uint8_t*)v_input;
  if (start_byte == 0)
    memset(ctx->keystream, 0, sizeof(uint64_t));
  else {
    uint64_t starting_block = start_byte / SKC_THREEFISH512_BLOCK_BYTES;
    int_fast8_t offset = start_byte % SKC_THREEFISH512_BLOCK_BYTES;
    int_fast8_t bytes  = SKC_THREEFISH512_BLOCK_BYTES - offset;
    ctx->keystream[0] = STORE64_(starting_block);
    Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
    INC_U64_(ctx->keystream);
    uint8_t* off = ctx->buffer + offset;
    int left;
    if (input_size >= (uint64_t)bytes)
      left = (int)bytes;
    else
      left = (int)input_size;
    for (int i = 0; i < left; ++i)
      off[i] ^= input[i];
    memcpy(output, off, left);
    input      += left;
    output     += left;
    input_size -= left;
  }
  while (input_size >= SKC_THREEFISH512_BLOCK_BYTES) {
    Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
    INC_U64_(ctx->keystream);
    Base_xor_64(ctx->buffer, input);
    memcpy(output, ctx->buffer, SKC_THREEFISH512_BLOCK_BYTES);
    input      += SKC_THREEFISH512_BLOCK_BYTES;
    output     += SKC_THREEFISH512_BLOCK_BYTES;
    input_size -= SKC_THREEFISH512_BLOCK_BYTES;
  }
  if (input_size) {
    Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
    BASE_STATIC_ASSERT(INT_FAST8_MAX > SKC_THREEFISH512_BLOCK_BYTES, "Should be impossible.");
    for (int_fast8_t i = 0; i < (int_fast8_t)input_size; ++i)
      ctx->buffer[i] ^= input[i];
    memcpy(output, ctx->buffer, input_size);
  }
}

void Skc_Threefish512_calc_ks_parity_words(uint64_t* const R_ key, uint64_t* const R_ twk)
{
  key[8] = STORE64_(
            SKC_THREEFISH512_CONSTANT_240 ^
            LOAD64_(key[0]) ^ LOAD64_(key[1]) ^
	    LOAD64_(key[2]) ^ LOAD64_(key[3]) ^
	    LOAD64_(key[4]) ^ LOAD64_(key[5]) ^
	    LOAD64_(key[6]) ^ LOAD64_(key[7])
	   );
  twk[2] = STORE64_(LOAD64_(twk[0]) ^ LOAD64_(twk[1]));
}
