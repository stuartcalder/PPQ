/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include "GraphHash.h"
#include "Skein512.h"

#define R_ SSC_RESTRICT

#define IDX_(BytePtr, Idx) \
 (BytePtr + ((Idx) * PPQ_THREEFISH512_BLOCK_BYTES))

/* Copy 64 bytes from @SrcPtr to @DestPtr. */
#define COPY_(DestPtr, SrcPtr) \
 memcpy(DestPtr, SrcPtr, PPQ_THREEFISH512_BLOCK_BYTES)

/* Hash 128 bytes at the @SrcPtr; store 64 bytes at the @DestPtr. */
#define HASH_(ContextPtr, DestPtr, SrcPtr) \
 PPQ_Skein512_hashNative(ContextPtr, DestPtr, SrcPtr, (PPQ_THREEFISH512_BLOCK_BYTES * 2))

static uint64_t
bitReversalIndex(uint64_t i, const uint8_t garlic)
{
  i = SSC_swap64(i);
  i = ((i & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4) |
      ((i & UINT64_C(0xf0f0f0f0f0f0f0f0)) >> 4);
  i = ((i & UINT64_C(0x3333333333333333)) << 2) |
      ((i & UINT64_C(0xcccccccccccccccc)) >> 2);
  i = ((i & UINT64_C(0x5555555555555555)) << 1) |
      ((i & UINT64_C(0xaaaaaaaaaaaaaaaa)) >> 1);
  return i >> (64 - garlic);
}

void PPQ_graphHash(
 PPQ_UBI512* const R_ ubi512,
 uint8_t* const R_    temp,
 uint8_t* const R_    graph,
 const uint8_t        garlic,
 const uint8_t        lambda)
{
  const uint64_t garlic_end = (UINT64_C(1) << garlic) - 1;
  for (uint8_t j = 1; j <= lambda; ++j) {
    COPY_(IDX_(temp, 0), IDX_(graph, garlic_end));
    COPY_(IDX_(temp, 1), IDX_(graph, 0));
    HASH_(ubi512, IDX_(graph, 0), IDX_(temp, 0));
    for (uint64_t i = 1; i <= garlic_end; ++i) {
      COPY_(IDX_(temp, 0), IDX_(graph, (i - 1)));
      COPY_(IDX_(temp, 1), IDX_(graph, bitReversalIndex(i, garlic)));
      HASH_(ubi512, IDX_(graph, i), IDX_(temp, 0));
    }
  }
}
