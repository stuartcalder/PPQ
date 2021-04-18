#include "csprng.h"

void
symm_csprng_reseed (Symm_CSPRNG *   SHIM_RESTRICT ctx,
		    uint8_t const * SHIM_RESTRICT seed)
{
	SHIM_STATIC_ASSERT(sizeof(ctx->buffer) == (SYMM_THREEFISH512_BLOCK_BYTES * 2), "Wrong buffer size.");
	memcpy(ctx->buffer, ctx->seed, SYMM_THREEFISH512_BLOCK_BYTES);
	memcpy(ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES, seed, SYMM_THREEFISH512_BLOCK_BYTES);
	symm_skein512_hash_native(&ctx->ubi512_ctx,
				  ctx->seed,
				  ctx->buffer,
				  sizeof(ctx->buffer));
	shim_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}
void
symm_csprng_os_reseed (Symm_CSPRNG * ctx) {
	SHIM_STATIC_ASSERT(sizeof(ctx->buffer) == (SYMM_THREEFISH512_BLOCK_BYTES * 2), "Wrong buffer size.");
	memcpy(ctx->buffer, ctx->seed, SYMM_THREEFISH512_BLOCK_BYTES);
	shim_obtain_os_entropy(ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES, SYMM_THREEFISH512_BLOCK_BYTES);
	symm_skein512_hash_native(&ctx->ubi512_ctx,
				  ctx->seed,
				  ctx->buffer,
				  sizeof(ctx->buffer));
	shim_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}

static uint8_t const SKEIN_PRECOMPUTED_CFG_ [SYMM_THREEFISH512_BLOCK_BYTES] = {
	0x54, 0x5e, 0x7a, 0x4c, 0x78, 0x32, 0xaf, 0xdb,
	0xc7, 0xab, 0x18, 0xd2, 0x87, 0xd9, 0xe6, 0x2d,
	0x41, 0x08, 0x90, 0x3a, 0xcb, 0xa9, 0xa3, 0xae,
	0x31, 0x08, 0xc7, 0xe4, 0x0e, 0x0e, 0x55, 0xa0,
	0xc3, 0x9c, 0xa8, 0x5d, 0x6c, 0xd2, 0x46, 0x71,
	0xba, 0x1b, 0x58, 0x66, 0x31, 0xa3, 0xfd, 0x33,
	0x87, 0x69, 0x83, 0x54, 0x3c, 0x17, 0x93, 0x02,
	0xd7, 0x59, 0x94, 0x61, 0x00, 0xb8, 0xb8, 0x07
};

#define SKEIN_PRE_CFG_IMPL_(ctx_p, output, input, input_size, output_size) \
	memcpy( ctx_p->key_state, SKEIN_PRECOMPUTED_CFG_, sizeof(SKEIN_PRECOMPUTED_CFG_) ); \
	symm_ubi512_chain_message( ctx_p, input, input_size ); \
	symm_ubi512_chain_output( ctx_p, output, output_size )
#define SKEIN_PRE_CFG_(ubi_p_v) \
	SKEIN_PRE_CFG_IMPL_ (ubi_p_v, ctx->buffer, ctx->seed, sizeof(ctx->seed), sizeof(ctx->buffer) )

void
symm_csprng_get (Symm_CSPRNG * SHIM_RESTRICT ctx,
		 uint8_t *     SHIM_RESTRICT output,
		 int64_t                     requested_bytes)
{
	if(!requested_bytes)
		return;
	Symm_UBI512 * ubi_p = &ctx->ubi512_ctx;
	while (requested_bytes > SYMM_THREEFISH512_BLOCK_BYTES) {
		SKEIN_PRE_CFG_ (ubi_p);
		memcpy(ctx->seed, ctx->buffer, SYMM_THREEFISH512_BLOCK_BYTES);
		memcpy(output, ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES, SYMM_THREEFISH512_BLOCK_BYTES);
		output          += SYMM_THREEFISH512_BLOCK_BYTES;
		requested_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
	}
	SKEIN_PRE_CFG_ (ubi_p);
	memcpy(ctx->seed, ctx->buffer, SYMM_THREEFISH512_BLOCK_BYTES);
	memcpy(output, ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES, requested_bytes);
	shim_secure_zero(ctx->buffer, sizeof(ctx->buffer));
}
