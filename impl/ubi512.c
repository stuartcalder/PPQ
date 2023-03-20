/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include <Base/mem.h>
#include "ubi512.h"

#define R_ BASE_RESTRICT

#define INIT_ENCIPHER_XOR_(Ctx) \
 Skc_UBI512_init_tf_ks(Ctx); \
 Skc_Threefish512_Dynamic_encipher(&Ctx->threefish512, Ctx->key_state, Ctx->msg_state); \
 Base_xor_64(Ctx->key_state, Ctx->msg_state)

#define MODIFY_TWEAK_FLAGS_(Ctx, Op, Val) \
 ((uint8_t*)Ctx->tweak_state)[SKC_THREEFISH512_TWEAK_BYTES - 1] Op Val

#if   BASE_ENDIAN == BASE_ENDIAN_LITTLE
 #define LOAD64_(Word64)  Word64
 #define STORE64_(Word64) Word64
#elif BASE_ENDIAN == BASE_ENDIAN_BIG
 #define LOAD64_(Word64)  Base_swap_64(Word64)
 #define STORE64_(Word64) Base_swap_64(Word64)
#else
 #error
#endif

#define SET_TWEAK_POSITION_(Ctx, Val)        Ctx->tweak_state[0] = STORE64_(Val)
#define MODIFY_TWEAK_POSITION_(Ctx, Op, Val) Ctx->tweak_state[0] = STORE64_(LOAD64_(Ctx->tweak_state[0]) Op Val)

#define INIT_TWEAK_(Ctx, Init_Or) \
	memset(Ctx->tweak_state, 0, SKC_THREEFISH512_TWEAK_BYTES); \
	MODIFY_TWEAK_FLAGS_(Ctx, |=, (SKC_UBI512_TWEAK_FIRST_BIT | Init_Or))

void
Skc_UBI512_chain_config(Skc_UBI512* const R_ ctx, const uint64_t num_out_bits)
{
  INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_CFG));
  SET_TWEAK_POSITION_(ctx, 32);
  static const uint8_t init [SKC_THREEFISH512_BLOCK_BYTES] = {
    /* Schema identifier "SHA3" version 1. */
    0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  memcpy(ctx->msg_state, init, sizeof(init));
  uint64_t nob = STORE64_(num_out_bits);
  memcpy(ctx->msg_state + 8, &nob, sizeof(nob));
  INIT_ENCIPHER_XOR_(ctx);
}

void
Skc_UBI512_chain_native_output(Skc_UBI512* const R_ ctx, uint8_t* R_ output)
{
  INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_OUT));
  SET_TWEAK_POSITION_(ctx, 8);
  memset(ctx->msg_state, 0, sizeof(ctx->msg_state));
  INIT_ENCIPHER_XOR_(ctx);
  memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
}

void
Skc_UBI512_chain_message(Skc_UBI512* const R_ ctx, const uint8_t* R_ input, uint64_t num_in_bytes)
{
  INIT_TWEAK_(ctx, SKC_UBI512_TYPEMASK_MSG);
  if (num_in_bytes <= SKC_THREEFISH512_BLOCK_BYTES) {
    MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
    SET_TWEAK_POSITION_(ctx, num_in_bytes);
    memcpy(ctx->msg_state, input, num_in_bytes);
    memset((ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes));
    INIT_ENCIPHER_XOR_(ctx);
    return;
  }
  SET_TWEAK_POSITION_(ctx, SKC_THREEFISH512_BLOCK_BYTES);
  memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
  INIT_ENCIPHER_XOR_(ctx);
  MODIFY_TWEAK_FLAGS_(ctx, &=, SKC_UBI512_TWEAK_FIRST_MASK);
  num_in_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
  input        += SKC_THREEFISH512_BLOCK_BYTES;
  while (num_in_bytes > SKC_THREEFISH512_BLOCK_BYTES) {
    MODIFY_TWEAK_POSITION_(ctx, +, SKC_THREEFISH512_BLOCK_BYTES);
    memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
    INIT_ENCIPHER_XOR_(ctx);
    num_in_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
    input        += SKC_THREEFISH512_BLOCK_BYTES;
  }
  MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
  MODIFY_TWEAK_POSITION_(ctx, +, num_in_bytes);
  memcpy(ctx->msg_state, input, num_in_bytes);
  memset((ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes));
  INIT_ENCIPHER_XOR_(ctx);
}
#define INC_U64_(Ptr) do {\
 uint64_t tmp;\
 memcpy(&tmp, Ptr, sizeof(tmp));\
 tmp = STORE64_(LOAD64_(tmp) + 1);\
 memcpy(Ptr, &tmp, sizeof(tmp));\
} while(0)

void
Skc_UBI512_chain_output(Skc_UBI512* const R_ ctx, uint8_t* R_ output, uint64_t num_out_bytes)
{
  /* We're doing at least one block. */
  INIT_TWEAK_(ctx, SKC_UBI512_TYPEMASK_OUT);
  memset(ctx->msg_state, 0, sizeof(ctx->msg_state));
  SET_TWEAK_POSITION_(ctx, 8);
  if (num_out_bytes <= SKC_THREEFISH512_BLOCK_BYTES) {
    MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
    INIT_ENCIPHER_XOR_(ctx);
    memcpy(output, ctx->key_state, num_out_bytes);
    return;
  }
  INIT_ENCIPHER_XOR_(ctx);
  MODIFY_TWEAK_FLAGS_(ctx, &=, SKC_UBI512_TWEAK_FIRST_MASK);
  memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
  INC_U64_(ctx->msg_state);
  num_out_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
  output        += SKC_THREEFISH512_BLOCK_BYTES;
  while (num_out_bytes > SKC_THREEFISH512_BLOCK_BYTES) {
    MODIFY_TWEAK_POSITION_(ctx, +, sizeof(uint64_t));
    INIT_ENCIPHER_XOR_(ctx);
    memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
    INC_U64_(ctx->msg_state);
    num_out_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
    output        += SKC_THREEFISH512_BLOCK_BYTES;
  }
  MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
  MODIFY_TWEAK_POSITION_(ctx, +, sizeof(uint64_t));
  INIT_ENCIPHER_XOR_(ctx);
  memcpy(output, ctx->key_state, num_out_bytes);
}

void
Skc_UBI512_chain_key(Skc_UBI512* const R_ ctx, const uint8_t* R_ input) {
  INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_KEY));
  SET_TWEAK_POSITION_(ctx, SKC_THREEFISH512_BLOCK_BYTES);
  memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
  INIT_ENCIPHER_XOR_(ctx);
}
