#include "skein512.h"

void 
symm_skein512_hash (Symm_UBI512 * SHIM_RESTRICT ubi512_ctx,
		    uint8_t *                   bytes_out,
		    uint8_t const *             bytes_in,
		    uint64_t const              num_bytes_in,
		    uint64_t const              num_bytes_out)
{
	memset( ubi512_ctx->key_state, 0, SYMM_THREEFISH512_BLOCK_BYTES );
	symm_ubi512_chain_config( ubi512_ctx, (num_bytes_out * CHAR_BIT) );
	symm_ubi512_chain_message( ubi512_ctx, bytes_in, num_bytes_in );
	symm_ubi512_chain_output( ubi512_ctx, bytes_out, num_bytes_out );
}

void
symm_skein512_hash_native (Symm_UBI512 * SHIM_RESTRICT ubi512_ctx,
			   uint8_t *                   bytes_out,
			   uint8_t const *             bytes_in,
			   uint64_t const              num_bytes_in)
{
	static uint64_t const init [8] = {
		UINT64_C (0x4903adff749c51ce),
		UINT64_C (0x0d95de399746df03),
		UINT64_C (0x8fd1934127c79bce),
		UINT64_C (0x9a255629ff352cb1),
		UINT64_C (0x5db62599df6ca7b0),
		UINT64_C (0xeabe394ca9d5c3f4),
		UINT64_C (0x991112c71a75b523),
		UINT64_C (0xae18a40b660fcc33)
	};
	SHIM_STATIC_ASSERT (sizeof(init) == SYMM_THREEFISH512_BLOCK_BYTES, "Wrong size");
	memcpy( ubi512_ctx->key_state, init, sizeof(init) );
	symm_ubi512_chain_message( ubi512_ctx, bytes_in, num_bytes_in );
	symm_ubi512_chain_native_output( ubi512_ctx, bytes_out );
}

void
symm_skein512_mac (Symm_UBI512 *   SHIM_RESTRICT ubi512_ctx,
		   uint8_t *                     bytes_out,
		   uint8_t const *               bytes_in,
		   uint8_t const * SHIM_RESTRICT key_in,
		   uint64_t const                num_bytes_in,
		   uint64_t const                num_bytes_out)
{
	memset( ubi512_ctx->key_state, 0, SYMM_THREEFISH512_BLOCK_BYTES );
	symm_ubi512_chain_key( ubi512_ctx, key_in );
	symm_ubi512_chain_config( ubi512_ctx, (num_bytes_out * CHAR_BIT) );
	symm_ubi512_chain_message( ubi512_ctx, bytes_in, num_bytes_in );
	symm_ubi512_chain_output( ubi512_ctx, bytes_out, num_bytes_out );
}



