/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include "Catena512.h"
#include "Macro.h"
#include "Skein512.h"

#include <inttypes.h>
#include <stdio.h>

#include <SSC/Memory.h>

#define R_    SSC_RESTRICT
#define AL64_ SSC_ALIGNAS(uint64_t)

#define IDX_(BytePtr, Index) \
  (BytePtr + ((Index) * PPQ_THREEFISH512_BLOCK_BYTES))

#define COPY_(DestPtr, SrcPtr) \
  memcpy(DestPtr, SrcPtr, PPQ_THREEFISH512_BLOCK_BYTES)

#define HASH_(Context, DestPtr, SrcPtr) \
  PPQ_Skein512_hashNative(\
   &Context->ubi512,\
   DestPtr,\
   SrcPtr,\
   (PPQ_THREEFISH512_BLOCK_BYTES * 2))

AL64_ static const uint8_t Without_Phi_Version_ID_Hash [PPQ_THREEFISH512_BLOCK_BYTES] = {
  0x79, 0xb5, 0x79, 0x1e, 0x9a, 0xac, 0x02, 0x64,
  0x2a, 0xaa, 0x99, 0x1b, 0xd5, 0x47, 0xed, 0x14,
  0x74, 0x4d, 0x72, 0xbf, 0x13, 0x22, 0x54, 0xc9,
  0xad, 0xd6, 0xb9, 0xbe, 0xe8, 0x70, 0x18, 0xe2,
  0xaa, 0x51, 0x50, 0xe2, 0x1f, 0xcd, 0x90, 0x19,
  0xb6, 0x1f, 0x0e, 0xc6, 0x05, 0x00, 0xd6, 0xed,
  0x7c, 0xf2, 0x03, 0x53, 0xfd, 0x42, 0xa5, 0xa3,
  0x7a, 0x0e, 0xbb, 0xb4, 0xa7, 0xeb, 0xdb, 0xab
};

AL64_ static const uint8_t With_Phi_Version_ID_Hash [PPQ_THREEFISH512_BLOCK_BYTES] = {
  0x1f, 0x23, 0x89, 0x58, 0x4a, 0x4a, 0xbb, 0xa5,
  0x9f, 0x09, 0xca, 0xd4, 0xef, 0xac, 0x43, 0x1d,
  0xde, 0x9a, 0xb0, 0xf8, 0x69, 0xaa, 0x50, 0xf3,
  0xed, 0xcc, 0xb4, 0x7d, 0x6d, 0x4f, 0x10, 0xb9,
  0x8e, 0x6a, 0x68, 0xab, 0x6e, 0x53, 0xbc, 0xd6,
  0xcf, 0xfc, 0xa7, 0x63, 0x94, 0x44, 0xbd, 0xc7,
  0xb9, 0x6d, 0x09, 0xf5, 0x66, 0x31, 0xa3, 0xc5,
  0xf3, 0x26, 0xeb, 0x6f, 0xa6, 0xac, 0xb0, 0xa6
};

static void
make_tweak_without_phi(PPQ_Catena512* R_, const uint8_t);

static void
make_tweak_with_phi(PPQ_Catena512* R_, const uint8_t);

static void
flap_without_phi(PPQ_Catena512* R_, const uint8_t, const uint8_t);

static void
flap_with_phi(PPQ_Catena512* R_, const uint8_t, const uint8_t);

static void
gamma(PPQ_Catena512* R_, const uint8_t);

static void
phi(PPQ_Catena512* R_, const uint8_t);

void make_tweak_without_phi(PPQ_Catena512* R_ ctx, const uint8_t lambda)
{
  uint8_t* t = ctx->temp.tw_pw_salt;
  memcpy(t, Without_Phi_Version_ID_Hash, PPQ_THREEFISH512_BLOCK_BYTES);
  t += PPQ_THREEFISH512_BLOCK_BYTES;
  (*t++) = PPQ_CATENA512_DOMAIN_KDF;
  (*t++) = lambda;
  (*t++) = (uint8_t)PPQ_THREEFISH512_BLOCK_BYTES;
  (*t++) = (uint8_t)((unsigned)PPQ_THREEFISH512_BLOCK_BYTES >> 8);
  (*t++) = (uint8_t)PPQ_CATENA512_SALT_BYTES;
  *t     = (uint8_t)((unsigned)PPQ_CATENA512_SALT_BYTES >> 8);
}
void make_tweak_with_phi(PPQ_Catena512* R_ ctx, const uint8_t lambda)
{
  uint8_t* t = ctx->temp.tw_pw_salt;
  memcpy(t, With_Phi_Version_ID_Hash, PPQ_THREEFISH512_BLOCK_BYTES);
  t += PPQ_THREEFISH512_BLOCK_BYTES;
  (*t++) = PPQ_CATENA512_DOMAIN_KDF;
  (*t++) = lambda;
  (*t++) = (uint8_t)PPQ_THREEFISH512_BLOCK_BYTES;
  (*t++) = (uint8_t)((unsigned)PPQ_THREEFISH512_BLOCK_BYTES >> 8);
  (*t++) = (uint8_t)PPQ_CATENA512_SALT_BYTES;
  *t     = (uint8_t)((unsigned)PPQ_CATENA512_SALT_BYTES >> 8);
}
void flap_without_phi(PPQ_Catena512* R_ ctx, const uint8_t garlic, const uint8_t lambda)
{
  #define TEMP_  ctx->temp.flap
  #define GRAPH_ ctx->graph_memory
  #define X_     ctx->x
  AL64_ static const uint8_t Config [PPQ_THREEFISH512_BLOCK_BYTES] = {
    0x54, 0x5e, 0x7a, 0x4c, 0x78, 0x32, 0xaf, 0xdb,
    0xc7, 0xab, 0x18, 0xd2, 0x87, 0xd9, 0xe6, 0x2d,
    0x41, 0x08, 0x90, 0x3a, 0xcb, 0xa9, 0xa3, 0xae,
    0x31, 0x08, 0xc7, 0xe4, 0x0e, 0x0e, 0x55, 0xa0,
    0xc3, 0x9c, 0xa8, 0x5d, 0x6c, 0xd2, 0x46, 0x71,
    0xba, 0x1b, 0x58, 0x66, 0x31, 0xa3, 0xfd, 0x33,
    0x87, 0x69, 0x83, 0x54, 0x3c, 0x17, 0x93, 0x02,
    0xd7, 0x59, 0x94, 0x61, 0x00, 0xb8, 0xb8, 0x07
  };
  memcpy(ctx->ubi512.key_state, Config, sizeof(Config));
  PPQ_UBI512_chainMessage(&ctx->ubi512, X_   , PPQ_THREEFISH512_BLOCK_BYTES);
  PPQ_UBI512_chainOutput(&ctx->ubi512 , TEMP_, (PPQ_THREEFISH512_BLOCK_BYTES * 2));
  HASH_(ctx, IDX_(TEMP_, 1), IDX_(TEMP_, 0));
  COPY_(IDX_(TEMP_, 2), IDX_(TEMP_, 0));
  HASH_(ctx, IDX_(TEMP_, 0), IDX_(TEMP_, 1));
  COPY_(IDX_(GRAPH_, 0), IDX_(TEMP_, 1));
  COPY_(IDX_(GRAPH_, 1), IDX_(TEMP_, 0));
  const uint64_t max_hash_index = (UINT64_C(1) << garlic) - 1;
  if (max_hash_index > 1) {
    HASH_(ctx, IDX_(TEMP_, 2), IDX_(TEMP_, 0));
    COPY_(IDX_(GRAPH_, 2), IDX_(TEMP_, 2));
    COPY_(IDX_(TEMP_, 1) , IDX_(TEMP_, 2));
    COPY_(IDX_(TEMP_, 2) , IDX_(TEMP_, 0));
    HASH_(ctx, IDX_(TEMP_, 0), IDX_(TEMP_, 1));
    COPY_(IDX_(GRAPH_, 3), IDX_(TEMP_, 0));
  }
  for (uint64_t i = 4; i <= max_hash_index; ++i) {
    HASH_(ctx, IDX_(TEMP_, 2), IDX_(TEMP_, 0));
    COPY_(IDX_(TEMP_,  1), IDX_(TEMP_, 0));
    COPY_(IDX_(TEMP_,  0), IDX_(TEMP_, 2));
    COPY_(IDX_(GRAPH_, i), IDX_(TEMP_, 0));
  }
  gamma(ctx, garlic);
  PPQ_graphHash(&ctx->ubi512, ctx->temp.mhf, GRAPH_, garlic, lambda);
  COPY_(X_, IDX_(GRAPH_, max_hash_index));
  #undef X_
  #undef GRAPH_
  #undef TEMP_
}
void flap_with_phi(PPQ_Catena512* R_ ctx, const uint8_t garlic, const uint8_t lambda)
{
  #define TEMP_  ctx->temp.flap
  #define GRAPH_ ctx->graph_memory
  #define X_     ctx->x
  AL64_ static uint8_t const Config [PPQ_THREEFISH512_BLOCK_BYTES] = {
    0x54,0x5e,0x7a,0x4c,0x78,0x32,0xaf,0xdb,
    0xc7,0xab,0x18,0xd2,0x87,0xd9,0xe6,0x2d,
    0x41,0x08,0x90,0x3a,0xcb,0xa9,0xa3,0xae,
    0x31,0x08,0xc7,0xe4,0x0e,0x0e,0x55,0xa0,
    0xc3,0x9c,0xa8,0x5d,0x6c,0xd2,0x46,0x71,
    0xba,0x1b,0x58,0x66,0x31,0xa3,0xfd,0x33,
    0x87,0x69,0x83,0x54,0x3c,0x17,0x93,0x02,
    0xd7,0x59,0x94,0x61,0x00,0xb8,0xb8,0x07
  };
  memcpy(ctx->ubi512.key_state, Config, sizeof(Config));
  PPQ_UBI512_chainMessage(&ctx->ubi512,   X_, PPQ_THREEFISH512_BLOCK_BYTES);
  PPQ_UBI512_chainOutput(&ctx->ubi512, TEMP_, (PPQ_THREEFISH512_BLOCK_BYTES * 2));
  HASH_(ctx, IDX_(TEMP_, 1), IDX_(TEMP_, 0));
  COPY_(IDX_(TEMP_, 2), IDX_(TEMP_, 0));
  HASH_(ctx, IDX_(TEMP_, 0), IDX_(TEMP_, 1));
  COPY_(IDX_(GRAPH_, 0), IDX_(TEMP_, 1));
  COPY_(IDX_(GRAPH_, 1), IDX_(TEMP_, 0));
  const uint64_t max_hash_index = (UINT64_C(1) << garlic) - 1;
  if (max_hash_index > 1) {
    HASH_(ctx, IDX_(TEMP_, 2), IDX_(TEMP_, 0));
    COPY_(IDX_(GRAPH_, 2), IDX_(TEMP_, 2));
    COPY_(IDX_(TEMP_, 1), IDX_(TEMP_, 2));
    COPY_(IDX_(TEMP_, 2), IDX_(TEMP_, 0));
    HASH_(ctx, IDX_(TEMP_, 0), IDX_(TEMP_, 1));
    COPY_(IDX_(GRAPH_, 3), IDX_(TEMP_, 0));
  }
  for (uint64_t i = 4; i <= max_hash_index; ++i) {
    HASH_(ctx, IDX_(TEMP_, 2), IDX_(TEMP_, 0));
    COPY_(IDX_(TEMP_, 1), IDX_(TEMP_, 0));
    COPY_(IDX_(TEMP_, 0), IDX_(TEMP_, 2));
    COPY_(IDX_(GRAPH_, i), IDX_(TEMP_, 0));
  }
  gamma(ctx, garlic);
  PPQ_graphHash(&ctx->ubi512, ctx->temp.mhf, GRAPH_, garlic, lambda);
  phi(ctx, garlic);
  #undef X_
  #undef GRAPH_
  #undef TEMP_
}
void phi(PPQ_Catena512* R_ ctx, const uint8_t garlic)
{
  #define GRAPH_ ctx->graph_memory
  #define TEMP_  ctx->temp.phi
  #define X_     ctx->x
  const uint64_t last_word_index = (UINT64_C(1) << garlic) - 1;
  const int right_shift_amt = 64 - garlic;
  uint64_t j = SSC_loadLittleEndian64(IDX_(GRAPH_, last_word_index));
  j >>= right_shift_amt;
  COPY_(IDX_(TEMP_, 0), IDX_(GRAPH_, last_word_index));
  COPY_(IDX_(TEMP_, 1), IDX_(GRAPH_, j));
  HASH_(ctx, IDX_(GRAPH_, 0), IDX_(TEMP_, 0));
  for (uint64_t i = 1; i <= last_word_index; ++i) {
    j = SSC_loadLittleEndian64(IDX_(GRAPH_, (i - 1)));
    j >>= right_shift_amt;
    COPY_(IDX_(TEMP_, 0), IDX_(GRAPH_, (i - 1)));
    COPY_(IDX_(TEMP_, 1), IDX_(GRAPH_, j));
    HASH_(ctx, IDX_(GRAPH_, i), IDX_(TEMP_, 0));
  }
  COPY_(X_, IDX_(GRAPH_, last_word_index));
  #undef X_
  #undef TEMP_
  #undef GRAPH_
}
void gamma(PPQ_Catena512* R_ ctx, const uint8_t garlic)
{
  #define GRAPH_		 ctx->graph_memory
  #define TEMP_			 ctx->temp.gamma
  #define SALT_AND_GARLIC_BYTES_ (sizeof(ctx->salt) + sizeof(uint8_t))
  #define RNG_OUTPUT_SIZE_	 (PPQ_THREEFISH512_BLOCK_BYTES + (sizeof(uint64_t) * 2))
  #define J1_OFFSET_		 PPQ_THREEFISH512_BLOCK_BYTES
  #define J2_OFFSET_		 (J1_OFFSET_ + sizeof(uint64_t))
  memcpy(TEMP_.rng, ctx->salt, sizeof(ctx->salt));
  *(TEMP_.rng + sizeof(ctx->salt)) = garlic;
  PPQ_Skein512_hashNative(&ctx->ubi512, TEMP_.rng, TEMP_.rng, SALT_AND_GARLIC_BYTES_);
  const uint64_t count = UINT64_C(1) << (((3 * garlic) + 3) / 4);
  const int right_shift_amt = 64 - garlic;
  for (uint64_t i = 0; i < count; ++i) {
    AL64_ static const uint8_t Config [PPQ_THREEFISH512_BLOCK_BYTES] = {
      0xf0, 0xef, 0xcb, 0xca, 0xbf, 0xd0, 0x04, 0x7b,
      0xc0, 0x5d, 0x3e, 0x3a, 0x1d, 0x53, 0xe4, 0x9f,
      0x07, 0xbf, 0x4f, 0xf5, 0xce, 0x67, 0x53, 0x53,
      0x9f, 0x0e, 0xf7, 0xfb, 0x22, 0xe6, 0xf4, 0xc3,
      0x74, 0xcc, 0xb9, 0xed, 0xc0, 0x50, 0x23, 0x81,
      0x65, 0x27, 0x7a, 0xc2, 0xb2, 0xea, 0xfb, 0x96,
      0xcb, 0x91, 0xe2, 0x97, 0x59, 0x94, 0x1f, 0x6d,
      0x51, 0xc3, 0x9f, 0xe5, 0x27, 0x31, 0xd1, 0xc5
    };
    COPY_(ctx->ubi512.key_state, Config);
    PPQ_UBI512_chainMessage(&ctx->ubi512, TEMP_.rng, PPQ_THREEFISH512_BLOCK_BYTES);
    PPQ_UBI512_chainOutput(&ctx->ubi512, TEMP_.rng, RNG_OUTPUT_SIZE_);
    uint64_t j1, j2;
    j1 = SSC_loadLittleEndian64(TEMP_.rng + J1_OFFSET_);
    j1 >>= right_shift_amt;
    j2 = SSC_loadLittleEndian64(TEMP_.rng + J2_OFFSET_);
    j2 >>= right_shift_amt;
    COPY_(IDX_(TEMP_.word_buf, 0), IDX_(GRAPH_, j1));
    COPY_(IDX_(TEMP_.word_buf, 1), IDX_(GRAPH_, j2));
    HASH_(ctx, IDX_(GRAPH_, j1), IDX_(TEMP_.word_buf, 0));
  }
  #undef J2_OFFSET_
  #undef J1_OFFSET_
  #undef RNG_OUTPUT_SIZE_
  #undef SALT_AND_GARLIC_BYTES_
  #undef TEMP_
  #undef GRAPH_
}
SSC_Error_t PPQ_Catena512_noPhi(
 PPQ_Catena512* R_ ctx,
 uint8_t* R_       output,
 const uint8_t* R_ password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda)
{
  /* Allocate the graph memory. Free it at the end of the procedure; return on alloc failure. */
  const uint64_t allocated_bytes = (UINT64_C(1) << (g_high + 6));
  ctx->graph_memory = (uint8_t*)malloc(allocated_bytes);
  if (!ctx->graph_memory)
    return PPQ_CATENA512_ALLOC_FAILURE;
  uint8_t* const tw = ctx->temp.tw_pw_salt;
  uint8_t* const pw = tw + PPQ_CATENA512_TWEAK_BYTES;
  uint8_t* const salt = pw + password_size;
  /* Construct the tweak in the beginning of the "Tweak, Password, Salt" buffer. */
  make_tweak_without_phi(ctx, lambda);
  /* Copy the password into the "Tweak, Password, Salt" buffer, right after the tweak. */
  memcpy(pw, password, password_size);
  /* Copy the salt into the "Tweak, Password, Salt" buffer, right after the password. */
  memcpy(salt, ctx->salt, sizeof(ctx->salt));
  /* Hash the "Tweak, Password, Salt" buffer into the "X" buffer. */
  PPQ_Skein512_hashNative(&ctx->ubi512, ctx->x, tw, password_size + (PPQ_CATENA512_TWEAK_BYTES + PPQ_CATENA512_SALT_BYTES));
  /* Initial flap. */
  flap_without_phi(ctx, (g_low + 1) / 2, lambda);
  /* Hash the "X" buffer into itself. */
  PPQ_Skein512_hashNative(
   &ctx->ubi512,
   ctx->x,
   ctx->x,
   sizeof(ctx->x));
  /* Iterate over the "garlics" with g, from g_low to g_high. */
  for (uint8_t g = g_low; g <= g_high; ++g) {
    /* Flap. */
    flap_without_phi(ctx, g, lambda);
    /* Set the first byte of the "Catena" buffer equal to the garlic. */
    *(ctx->temp.catena) = g;
    /* Copy the "X" buffer into the "Catena" buffer, right after the garlic. */
    COPY_(ctx->temp.catena + sizeof(uint8_t), ctx->x);
    /* Hash the "Catena" buffer into the "X" buffer. */
    PPQ_Skein512_hashNative(
     &ctx->ubi512,
     ctx->x,
     ctx->temp.catena,
     sizeof(ctx->temp.catena));
  }
  /* Zero over and free the memory. Copy the buffer out of the procedure. */
  SSC_secureZero(ctx->graph_memory, allocated_bytes);
  free(ctx->graph_memory);
  COPY_(output, ctx->x);
  return PPQ_CATENA512_SUCCESS;
}
SSC_Error_t PPQ_Catena512_usePhi(
 PPQ_Catena512* R_ ctx,
 uint8_t* R_       output,
 const uint8_t* R_ password,
 const int         password_size,
 const uint8_t     g_low,
 const uint8_t     g_high,
 const uint8_t     lambda)
{
  /* Allocate the graph memory. Free it at the end of the procedure; return on alloc failure. */
  const uint64_t allocated_bytes = UINT64_C(1) << (g_high + 6);
  ctx->graph_memory = (uint8_t*)malloc(allocated_bytes);
  if (!ctx->graph_memory)
    return PPQ_CATENA512_ALLOC_FAILURE;
  uint8_t* const tw = ctx->temp.tw_pw_salt;
  uint8_t* const pw = tw + PPQ_CATENA512_TWEAK_BYTES;
  uint8_t* const salt = pw + password_size;
  /* Construct the tweak; concatenate with password and salt and hash into the x buffer. */
  make_tweak_with_phi(ctx, lambda);
  memcpy(pw, password, password_size);
  memcpy(salt, ctx->salt, sizeof(ctx->salt));
  PPQ_Skein512_hashNative(&ctx->ubi512, ctx->x, tw, password_size + (PPQ_CATENA512_TWEAK_BYTES + PPQ_CATENA512_SALT_BYTES));
  /* Initial flap; hash the x buffer into itself. */
  flap_with_phi(ctx, (g_low + 1) / 2, lambda);
  PPQ_Skein512_hashNative(&ctx->ubi512, ctx->x, ctx->x, sizeof(ctx->x));
  for (uint8_t g = g_low; g <= g_high; ++g) {
    /* Iterating flap over incrementing garlics of g, hashing the output
     * into the x buffer. */
    flap_with_phi(ctx, g, lambda);
    *(ctx->temp.catena) = g;
    COPY_(ctx->temp.catena + sizeof(uint8_t), ctx->x);
    PPQ_Skein512_hashNative(
     &ctx->ubi512,
     ctx->x,
     ctx->temp.catena,
     sizeof(ctx->temp.catena));
  }
  /* Zero over and free the memory. Copy the buffer out of the procedure. */
  SSC_secureZero(ctx->graph_memory, allocated_bytes);
  free(ctx->graph_memory);
  COPY_(output, ctx->x);
  return PPQ_CATENA512_SUCCESS;
}
