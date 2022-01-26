#include <Base/mem.h>
#include "threefish512.h"
#include <stdint.h>

#define R_(ptr) ptr BASE_RESTRICT
typedef Skc_Threefish512_Static  Static_t;
typedef Skc_Threefish512_Dynamic Dynamic_t;
typedef Skc_Threefish512_CTR     Ctr_t;

void
Skc_Threefish512_Static_init
(R_(Static_t* const) ctx,
 R_(uint64_t* const) key,
 R_(uint64_t* const) twk)
{
#define LOAD_WORD_(key, subkey, i) \
  Base_load_le64(key + (((subkey) + i) % SKC_THREEFISH512_EXTERNAL_KEY_WORDS))
#define STORE_WORD_(subkey, i, add) \
  Base_store_le64( \
   ctx->key_schedule + (((subkey) * SKC_THREEFISH512_BLOCK_WORDS) + i), \
   LOAD_WORD_(key, (subkey), i) + add \
  )
#define MAKE_SUBKEY_(subkey) \
  STORE_WORD_(subkey, 0, UINT64_C(0)); \
  STORE_WORD_(subkey, 1, UINT64_C(0)); \
  STORE_WORD_(subkey, 2, UINT64_C(0)); \
  STORE_WORD_(subkey, 3, UINT64_C(0)); \
  STORE_WORD_(subkey, 4, UINT64_C(0)); \
  STORE_WORD_(subkey, 5, Base_load_le64(twk + ((subkey) % 3))); \
  STORE_WORD_(subkey, 6, Base_load_le64(twk + (((subkey) + 1) % 3))); \
  STORE_WORD_(subkey, 7, (subkey))
#define MAKE_4_SUBKEYS_(start_skey) do { \
		MAKE_SUBKEY_(start_skey + 0); \
		MAKE_SUBKEY_(start_skey + 1); \
		MAKE_SUBKEY_(start_skey + 2); \
		MAKE_SUBKEY_(start_skey + 3); \
	} while (0)
	Skc_Threefish512_calc_ks_parity_words(key, twk);
	MAKE_4_SUBKEYS_(0);
	MAKE_4_SUBKEYS_(4);
	MAKE_4_SUBKEYS_(8);
	MAKE_4_SUBKEYS_(12);
	MAKE_SUBKEY_(16);
	MAKE_SUBKEY_(17);
	MAKE_SUBKEY_(18);
}

void
Skc_Threefish512_Static_encipher
(R_(Static_t* const)  ctx,
 void* const       v_ctext,
 const void* const v_ptext)
{
  uint8_t* const       ctext = (uint8_t*)      v_ctext;
  const uint8_t* const ptext = (const uint8_t*)v_ptext;
#define DO_MIX_(idx, rot_const) do { \
  uint64_t w0, w1; \
  w0 = Base_load_le64(ctx->state + ((idx) * 2)); \
  w1 = Base_load_le64(ctx->state + (((idx) * 2) + 1)); \
  w0 += w1; \
  Base_store_le64(ctx->state + ((idx) * 2), w0); \
  w1 = Base_rotl_64(w1, rot_const) ^ w0; \
  Base_store_le64(ctx->state + (((idx) * 2) + 1), w1); \
} while (0)
/* Rounds 0-3 use subkey idx 0, 4-7 use subkey idx 1, etc. */
#define SUBKEY_INDEX_(round) ((round) / 4)
#define SKI_(rnd) SUBKEY_INDEX_(rnd)
/* What is the offset of this round's subkey? */
#define SUBKEY_OFFSET_(round) (SKI_(round) * SKC_THREEFISH512_BLOCK_WORDS)
#define SKO_(rnd) SUBKEY_OFFSET_(rnd)
#define USE_SUBKEY_(op, rnd) do { \
  uint64_t st, ks; \
  st = Base_load_le64(ctx->state + 0); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 0)); \
  Base_store_le64(ctx->state + 0, st op ks); \
  st = Base_load_le64(ctx->state + 1); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 1)); \
  Base_store_le64(ctx->state + 1, st op ks); \
  st = Base_load_le64(ctx->state + 2); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 2)); \
  Base_store_le64(ctx->state + 2, st op ks); \
  st = Base_load_le64(ctx->state + 3); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 3)); \
  Base_store_le64(ctx->state + 3, st op ks); \
  st = Base_load_le64(ctx->state + 4); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 4)); \
  Base_store_le64(ctx->state + 4, st op ks); \
  st = Base_load_le64(ctx->state + 5); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 5)); \
  Base_store_le64(ctx->state + 5, st op ks); \
  st = Base_load_le64(ctx->state + 6); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 6)); \
  Base_store_le64(ctx->state + 6, st op ks); \
  st = Base_load_le64(ctx->state + 7); \
  ks = Base_load_le64(ctx->key_schedule + (SKO_(rnd) + 7)); \
  Base_store_le64(ctx->state + 7, st op ks); \
} while (0)
#define ADD_SUBKEY_(rnd)      USE_SUBKEY_(+, rnd)
#define SUBTRACT_SUBKEY_(rnd) USE_SUBKEY_(-, rnd)
#define PERMUTE_ do { \
		uint64_t w0, w1; \
		w0 = ctx->state[6]; \
		ctx->state[6] = ctx->state[0]; \
		w1 = ctx->state[4]; \
		ctx->state[4] = w0; \
		w0 = ctx->state[2]; \
		ctx->state[2] = w1; \
		ctx->state[0] = w0; \
		w0 = ctx->state[3]; \
		ctx->state[3] = ctx->state[7]; \
		ctx->state[7] = w0; \
	} while (0)
#define MIX4_PERM_(rc0, rc1, rc2, rc3) \
 DO_MIX_(0, rc0); DO_MIX_(1, rc1); \
 DO_MIX_(2, rc2); DO_MIX_(3, rc3); \
 PERMUTE_
#define ENC_ROUND_(rnd_start, rc0_0, rc0_1, rc0_2, rc0_3, \
                              rc1_0, rc1_1, rc1_2, rc1_3, \
			      rc2_0, rc2_1, rc2_2, rc2_3, \
			      rc3_0, rc3_1, rc3_2, rc3_3) \
 ADD_SUBKEY_(rnd_start); \
 MIX4_PERM_(rc0_0, rc0_1, rc0_2, rc0_3); \
 MIX4_PERM_(rc1_0, rc1_1, rc1_2, rc1_3); \
 MIX4_PERM_(rc2_0, rc2_1, rc2_2, rc2_3); \
 MIX4_PERM_(rc3_0, rc3_1, rc3_2, rc3_3)
#define ENC_ROUND_PHASE_0_(rnd_start) ENC_ROUND_(rnd_start, 46, 36, 19, 37, \
                                                            33, 27, 14, 42, \
							    17, 49, 36, 39, \
							    44,  9, 54, 56)
#define ENC_ROUND_PHASE_1_(rnd_start) ENC_ROUND_(rnd_start, 39, 30, 34, 24, \
                                                            13, 50, 10, 17, \
							    25, 29, 39, 43, \
							     8, 35, 56, 22)
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

void
Skc_Threefish512_Dynamic_encipher
(R_(Dynamic_t* const) ctx,
 void* const          v_ctext,
 const void* const    v_ptext)
{
  uint8_t* const       ctext = (uint8_t*)      v_ctext;
  const uint8_t* const ptext = (const uint8_t*)v_ptext;
#undef USE_SUBKEY_
#define USE_SUBKEY_(op, rnd) do { \
  uint64_t st, ek, et; \
  st = Base_load_le64(ctx->state + 0); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 0); \
  Base_store_le64(ctx->state + 0, st op ek); \
  st = Base_load_le64(ctx->state + 1); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 1); \
  Base_store_le64(ctx->state + 1, st op ek); \
  st = Base_load_le64(ctx->state + 2); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 2); \
  Base_store_le64(ctx->state + 2, st op ek); \
  st = Base_load_le64(ctx->state + 3); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 3); \
  Base_store_le64(ctx->state + 3, st op ek); \
  st = Base_load_le64(ctx->state + 4); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 4); \
  Base_store_le64(ctx->state + 4, st op ek); \
  st = Base_load_le64(ctx->state + 5); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 5); \
  et = Base_load_le64(ctx->extern_tweak + (SKI_(rnd) % 3)); \
  Base_store_le64(ctx->state + 5, st op (ek + et)); \
  st = Base_load_le64(ctx->state + 6); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 6); \
  et = Base_load_le64(ctx->extern_tweak + ((SKI_(rnd) + 1) % 3)); \
  Base_store_le64(ctx->state + 6, st op (ek + et)); \
  st = Base_load_le64(ctx->state + 7); \
  ek = LOAD_WORD_(ctx->extern_key, SKI_(rnd), 7); \
  et = SKI_(rnd); \
  Base_store_le64(ctx->state + 7, st op (ek + et)); \
} while (0)
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

void
Skc_Threefish512_CTR_init
(R_(Ctr_t* const)      ctx,
 R_(const void* const) init_vec)
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
   * be initialized during $Skc_Threefish512_CTR_xor_keystream.
   */
}

void
Skc_Threefish512_CTR_xor_keystream
(R_(Ctr_t* const) ctx,
 void*            v_output,
 const void*      v_input,
 uint64_t         input_size,
 uint64_t         start_byte)
{
	uint8_t*       output = (uint8_t*)      v_output;
	const uint8_t* input  = (const uint8_t*)v_input;
#define INC_U64_(u64p) Base_store_le64(u64p, Base_load_le64(u64p) + UINT64_C(1))
	if (start_byte == 0)
		memset(ctx->keystream, 0, sizeof(uint64_t));
	else {
		uint64_t starting_block = start_byte / SKC_THREEFISH512_BLOCK_BYTES;
		int_fast8_t offset = start_byte % SKC_THREEFISH512_BLOCK_BYTES;
		int_fast8_t bytes  = SKC_THREEFISH512_BLOCK_BYTES - offset;
		Base_store_le64(ctx->keystream, starting_block);
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

void
Skc_Threefish512_calc_ks_parity_words
(R_(uint64_t* const) key,
 R_(uint64_t* const) twk)
{
  Base_store_le64(
   key + 8,
   SKC_THREEFISH512_CONSTANT_240 ^
   Base_load_le64(key + 0) ^
   Base_load_le64(key + 1) ^
   Base_load_le64(key + 2) ^
   Base_load_le64(key + 3) ^
   Base_load_le64(key + 4) ^
   Base_load_le64(key + 5) ^
   Base_load_le64(key + 6) ^
   Base_load_le64(key + 7)
  );
  Base_store_le64(
   twk + 2,
   Base_load_le64(twk + 0) ^ Base_load_le64(twk + 1)
  );
}
