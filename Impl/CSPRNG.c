/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include "CSPRNG.h"
#include "Skein512.h"

#define R_ SSC_RESTRICT

void PPQ_CSPRNG_reseed(
 PPQ_CSPRNG* R_ ctx,
 const void* R_ v_entropy)
{
  const uint8_t* entropy  = (const uint8_t*)v_entropy;
  uint8_t* const first_64 = ctx->buffer;
  uint8_t* const last_64  = first_64 + PPQ_THREEFISH512_BLOCK_BYTES;
  memcpy(first_64, ctx->seed, PPQ_THREEFISH512_BLOCK_BYTES);
  memcpy(last_64 , entropy  , PPQ_THREEFISH512_BLOCK_BYTES);
  PPQ_Skein512_hashNative(&ctx->ubi512, ctx->seed, ctx->buffer, sizeof(ctx->buffer));
  SSC_secureZero(ctx->buffer, sizeof(ctx->buffer));
}
void PPQ_CSPRNG_reseedFromOS(PPQ_CSPRNG* ctx)
{
  uint8_t* const first_64 = ctx->buffer;
  uint8_t* const last_64 = first_64 + PPQ_THREEFISH512_BLOCK_BYTES;
  memcpy(first_64, ctx->seed, PPQ_THREEFISH512_BLOCK_BYTES);
  SSC_getEntropy(last_64, PPQ_THREEFISH512_BLOCK_BYTES);
  PPQ_Skein512_hashNative(&ctx->ubi512, ctx->seed, ctx->buffer, sizeof(ctx->buffer));
  SSC_secureZero(ctx->buffer, sizeof(ctx->buffer));
}
static const uint8_t skein_precomputed_cfg [PPQ_THREEFISH512_BLOCK_BYTES] = {
  0x54, 0x5e, 0x7a, 0x4c, 0x78, 0x32, 0xaf, 0xdb,
  0xc7, 0xab, 0x18, 0xd2, 0x87, 0xd9, 0xe6, 0x2d,
  0x41, 0x08, 0x90, 0x3a, 0xcb, 0xa9, 0xa3, 0xae,
  0x31, 0x08, 0xc7, 0xe4, 0x0e, 0x0e, 0x55, 0xa0,
  0xc3, 0x9c, 0xa8, 0x5d, 0x6c, 0xd2, 0x46, 0x71,
  0xba, 0x1b, 0x58, 0x66, 0x31, 0xa3, 0xfd, 0x33,
  0x87, 0x69, 0x83, 0x54, 0x3c, 0x17, 0x93, 0x02,
  0xd7, 0x59, 0x94, 0x61, 0x00, 0xb8, 0xb8, 0x07
};
#define SKEIN_PRE_CFG_(ContextPtr, Output, Input, Input_size, Output_size) \
 memcpy(ContextPtr->key_state, skein_precomputed_cfg, sizeof(skein_precomputed_cfg));\
 PPQ_UBI512_chainMessage(ContextPtr, Input, Input_size);\
 PPQ_UBI512_chainOutput(ContextPtr, Output, Output_size)
void PPQ_CSPRNG_get(
 PPQ_CSPRNG* R_ ctx,
 void* R_       v_output,
 uint64_t       num_bytes)
{
  uint8_t* output = (uint8_t*)v_output;
  if (!num_bytes)
    return;
  PPQ_UBI512* const ubi512_p = &ctx->ubi512;
  uint8_t* const first_64 = ctx->buffer;
  uint8_t* const last_64 = first_64 + PPQ_THREEFISH512_BLOCK_BYTES;
  while (num_bytes > PPQ_THREEFISH512_BLOCK_BYTES) {
    SKEIN_PRE_CFG_(ubi512_p, ctx->buffer, ctx->seed, sizeof(ctx->seed), sizeof(ctx->buffer));
    memcpy(ctx->seed, first_64, PPQ_THREEFISH512_BLOCK_BYTES);
    memcpy(output   , last_64 , PPQ_THREEFISH512_BLOCK_BYTES);
    output    += PPQ_THREEFISH512_BLOCK_BYTES;
    num_bytes -= PPQ_THREEFISH512_BLOCK_BYTES;
  }
  SKEIN_PRE_CFG_(ubi512_p, ctx->buffer, ctx->seed, sizeof(ctx->seed), sizeof(ctx->buffer));
  memcpy(ctx->seed, first_64, PPQ_THREEFISH512_BLOCK_BYTES);
  memcpy(output   , last_64 , num_bytes);
  SSC_secureZero(ctx->buffer, sizeof(ctx->buffer));
}
