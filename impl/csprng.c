#include "csprng.h"

void SHIM_PUBLIC
symm_csprng_reseed (Symm_CSPRNG *   SHIM_RESTRICT ctx,
		    uint8_t const * SHIM_RESTRICT seed)
{
	memcpy( ctx->buffer,
		ctx->seed,
		SYMM_THREEFISH512_BLOCK_BYTES );
	memcpy( ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES,
		seed,
		SYMM_THREEFISH512_BLOCK_BYTES );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->seed,
				   ctx->buffer,
				   sizeof(ctx->buffer) );
	shim_secure_zero( ctx->buffer, sizeof(ctx->buffer) );
}
void SHIM_PUBLIC
symm_csprng_os_reseed (Symm_CSPRNG * ctx)
{
	SHIM_STATIC_ASSERT (sizeof(ctx->buffer) == (SYMM_THREEFISH512_BLOCK_BYTES * 2), "Wrong buffer size.");
	memcpy( ctx->buffer,
		ctx->seed,
		SYMM_THREEFISH512_BLOCK_BYTES );
	shim_obtain_os_entropy( ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES,
				SYMM_THREEFISH512_BLOCK_BYTES );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->seed,
				   ctx->buffer,
				   sizeof(ctx->buffer) );
	shim_secure_zero( ctx->buffer, sizeof(ctx->buffer) );
}
void SHIM_PUBLIC
symm_csprng_get (Symm_CSPRNG * SHIM_RESTRICT ctx,
		 uint8_t *     SHIM_RESTRICT output,
		 uint64_t                    requested_bytes)
{
	while( requested_bytes > SYMM_THREEFISH512_BLOCK_BYTES ) {
		symm_skein512_hash( &ctx->ubi512_ctx,
				    ctx->buffer,
				    ctx->seed,
				    sizeof(ctx->seed),
				    sizeof(ctx->buffer) );
		memcpy( ctx->seed,
			ctx->buffer,
			SYMM_THREEFISH512_BLOCK_BYTES );
		memcpy( output,
			ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES,
			SYMM_THREEFISH512_BLOCK_BYTES );
		output          += SYMM_THREEFISH512_BLOCK_BYTES;
		requested_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
	}
	symm_skein512_hash( &ctx->ubi512_ctx,
			    ctx->buffer,
			    ctx->seed,
			    sizeof(ctx->seed),
			    sizeof(ctx->buffer) );
	memcpy( ctx->seed,
		ctx->buffer,
		SYMM_THREEFISH512_BLOCK_BYTES );
	memcpy( output,
		ctx->buffer + SYMM_THREEFISH512_BLOCK_BYTES,
		requested_bytes );
	shim_secure_zero( ctx->buffer, sizeof(ctx->buffer) );
}
