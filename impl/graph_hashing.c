/* Copyright (c) 2020-2022 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information.
 */
#include "graph_hashing.h"
#include "skein512.h"

#define R_(ptr) ptr BASE_RESTRICT
#define INDEX_(u8p, i)		(u8p + ((i) * SKC_THREEFISH512_BLOCK_BYTES))
#define COPY_(dest, src) 	memcpy(dest, src, SKC_THREEFISH512_BLOCK_BYTES)
#define HASH_(ubi_p, dest, src) Skc_Skein512_hash_native(ubi_p, dest, src, (SKC_THREEFISH512_BLOCK_BYTES * 2))

static uint64_t bit_reversal_index (uint64_t i, const uint8_t garlic) {
	i = Base_swap_64(i);
	i = ((i & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4) |
	    ((i & UINT64_C(0xf0f0f0f0f0f0f0f0)) >> 4);
	i = ((i & UINT64_C(0x3333333333333333)) << 2) |
	    ((i & UINT64_C(0xcccccccccccccccc)) >> 2);
	i = ((i & UINT64_C(0x5555555555555555)) << 1) |
	    ((i & UINT64_C(0xaaaaaaaaaaaaaaaa)) >> 1);
	return i >> (64 - garlic);
}

void Skc_graph_hash (R_(Skc_UBI512* const) ubi512,
                     R_(uint8_t* const)    temp,
		     R_(uint8_t* const)    graph,
		     const uint8_t         garlic,
		     const uint8_t         lambda)
{
	const uint64_t garlic_end = (UINT64_C(1) << garlic) - 1;
	for (uint8_t j = 1; j <= lambda; ++j) {
		COPY_(INDEX_(temp, 0), INDEX_(graph, garlic_end));
		COPY_(INDEX_(temp, 1), INDEX_(graph, 0));
		HASH_(ubi512, INDEX_(graph, 0), INDEX_(temp, 0));
		for (uint64_t i = 1; i <= garlic_end; ++i) {
			COPY_(INDEX_(temp,       0),
			      INDEX_(graph, (i - 1)));
			COPY_(INDEX_(temp, 1),
			      INDEX_(graph, bit_reversal_index(i, garlic)));
			HASH_(ubi512, INDEX_(graph, i), INDEX_(temp, 0));
		}
	}
}
