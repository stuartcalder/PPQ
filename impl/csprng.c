/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include "csprng.h"
#include "skein512.h"

#define R_ BASE_RESTRICT

void Skc_CSPRNG_reseed(
 Skc_CSPRNG* R_ ctx,
 const void* R_ v_entropy)
{
  const uint8_t* entropy = (const uint8_t*)v_entropy;
  uint8_t* const word_0 = ctx->buffer;
  uint8_t* const word_1 = word_0 + SKC_THREEFISH512_BLOCK_BYTES;
  memcpy(word_0, ctx->seed, SKC_THREEFISH512_BLOCK_BYTES);
  memcpy(word_1, entropy  , SKC_THREEFISH512_BLOCK_BYTES);
  Skc_Skein512_hash_native(&ctx->ubi512, ctx->seed, ctx->buffer, sizeof(ctx->buffer));
  Base_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}

void Skc_CSPRNG_os_reseed(Skc_CSPRNG* ctx)
{
  uint8_t* const word_0 = ctx->buffer;
  uint8_t* const word_1 = word_0 + SKC_THREEFISH512_BLOCK_BYTES;
  memcpy(word_0, ctx->seed, SKC_THREEFISH512_BLOCK_BYTES);
  Base_get_os_entropy(word_1, SKC_THREEFISH512_BLOCK_BYTES);
  Skc_Skein512_hash_native(&ctx->ubi512, ctx->seed, ctx->buffer, sizeof(ctx->buffer));
  Base_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}

static const uint8_t SKEIN_PRECOMPUTED_CFG_ [SKC_THREEFISH512_BLOCK_BYTES] = {
  0x54, 0x5e, 0x7a, 0x4c, 0x78, 0x32, 0xaf, 0xdb,
  0xc7, 0xab, 0x18, 0xd2, 0x87, 0xd9, 0xe6, 0x2d,
  0x41, 0x08, 0x90, 0x3a, 0xcb, 0xa9, 0xa3, 0xae,
  0x31, 0x08, 0xc7, 0xe4, 0x0e, 0x0e, 0x55, 0xa0,
  0xc3, 0x9c, 0xa8, 0x5d, 0x6c, 0xd2, 0x46, 0x71,
  0xba, 0x1b, 0x58, 0x66, 0x31, 0xa3, 0xfd, 0x33,
  0x87, 0x69, 0x83, 0x54, 0x3c, 0x17, 0x93, 0x02,
  0xd7, 0x59, 0x94, 0x61, 0x00, 0xb8, 0xb8, 0x07
};

#define SKEIN_PRE_CFG_(ctx_p, output, input, input_size, output_size) \
 memcpy(ctx_p->key_state, SKEIN_PRECOMPUTED_CFG_, sizeof(SKEIN_PRECOMPUTED_CFG_));\
 Skc_UBI512_chain_message(ctx_p, input, input_size);\
 Skc_UBI512_chain_output(ctx_p, output, output_size)

void Skc_CSPRNG_get(
 Skc_CSPRNG* R_ ctx,
 void* R_       v_output,
 uint64_t       num_bytes)
{
  uint8_t* output = (uint8_t*)v_output;
  if (!num_bytes) return;
  Skc_UBI512* const ubi512_p = &ctx->ubi512;
  uint8_t* const word_0 = ctx->buffer;
  uint8_t* const word_1 = word_0 + SKC_THREEFISH512_BLOCK_BYTES;
  while (num_bytes > SKC_THREEFISH512_BLOCK_BYTES) {
    SKEIN_PRE_CFG_(ubi512_p, ctx->buffer, ctx->seed, sizeof(ctx->seed), sizeof(ctx->buffer));
    memcpy(ctx->seed, word_0, SKC_THREEFISH512_BLOCK_BYTES);
    memcpy(output   , word_1, SKC_THREEFISH512_BLOCK_BYTES);
    output    += SKC_THREEFISH512_BLOCK_BYTES;
    num_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
  }
  SKEIN_PRE_CFG_(ubi512_p, ctx->buffer, ctx->seed, sizeof(ctx->seed), sizeof(ctx->buffer));
  memcpy(ctx->seed, word_0, SKC_THREEFISH512_BLOCK_BYTES);
  memcpy(output   , word_1, num_bytes);
  Base_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}
