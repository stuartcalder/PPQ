#include "graph_hashing.h"
#include "skein512.h"

#define INDEX_HASH_WORD_(ptr, index) \
	(ptr + (index * SYMM_THREEFISH512_BLOCK_BYTES))
#define COPY_HASH_WORD_(dest, src) \
	memcpy( dest, src, SYMM_THREEFISH512_BLOCK_BYTES )
#define HASH_TWO_WORDS_(ubi_ptr, dest, src) \
	symm_skein512_hash_native( ubi_ptr, \
				   dest, \
				   src, \
				   (SYMM_THREEFISH512_BLOCK_BYTES * 2) )

static uint64_t
bit_reversal_index_ (uint64_t i, uint8_t const garlic)
{
	i = shim_swap_64( i );
	i = ((i & UINT64_C (0x0f0f0f0f0f0f0f0f)) << 4) |
	    ((i & UINT64_C (0xf0f0f0f0f0f0f0f0)) >> 4);
	i = ((i & UINT64_C (0x3333333333333333)) << 2) |
	    ((i & UINT64_C (0xcccccccccccccccc)) >> 2);
	i = ((i & UINT64_C (0x5555555555555555)) << 1) |
	    ((i & UINT64_C (0xaaaaaaaaaaaaaaaa)) >> 1);
	return i >> (64 - garlic);
}

void
symm_graph_hash (Symm_UBI512 * SHIM_RESTRICT ubi512_ctx,
		 uint8_t *     SHIM_RESTRICT temp,
		 uint8_t *     SHIM_RESTRICT graph_memory,
		 uint8_t const               garlic,
		 uint8_t const               lambda)
{
	uint64_t const garlic_end = (UINT64_C (1) << garlic) - 1;
	for( uint8_t j = 1; j <= lambda; ++j ) {
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (temp, 0),
				 INDEX_HASH_WORD_ (graph_memory, garlic_end));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (temp, 1),
				 INDEX_HASH_WORD_ (graph_memory, bit_reversal_index_( UINT64_C (0), garlic )));
		HASH_TWO_WORDS_ (ubi512_ctx,
				 INDEX_HASH_WORD_ (graph_memory, 0),
				 INDEX_HASH_WORD_ (temp, 0));
		for( uint64_t i = 1; i <= garlic_end; ++i ) {
			COPY_HASH_WORD_ (INDEX_HASH_WORD_ (temp, 0),
					 INDEX_HASH_WORD_ (graph_memory, (i - 1)));
			COPY_HASH_WORD_ (INDEX_HASH_WORD_ (temp, 1),
					 INDEX_HASH_WORD_ (graph_memory, bit_reversal_index_( i, garlic )));
			HASH_TWO_WORDS_ (ubi512_ctx,
					 INDEX_HASH_WORD_ (graph_memory, i),
					 INDEX_HASH_WORD_ (temp, 0));
		}
	}
}
