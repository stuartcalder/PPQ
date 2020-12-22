#include "ubi512.h"

#define REKEY_CIPHER_XOR_(ctx_p) \
	symm_threefish512_ondemand_rekey( &ctx_p->threefish_ctx, \
					  ctx_p->key_state, \
					  ctx_p->tweak_state ); \
	symm_threefish512_ondemand_cipher( &ctx_p->threefish_ctx, \
					   (uint8_t *)ctx_p->key_state, \
					   ctx_p->msg_state ); \
	shim_xor_64( ctx_p->key_state, ctx_p->msg_state )
					  
#define MODIFY_TWEAK_FLAGS_(ctx_p, operation, value) \
	((uint8_t *)ctx_p->tweak_state)[ SYMM_THREEFISH512_TWEAK_BYTES - 1 ] operation value

#define MODIFY_TWEAK_POSITION_(ctx_p, operation, value) \
	ctx_p->tweak_state[ 0 ] operation value

#define INIT_TWEAK_(ctx_p, init_bitwise_or) \
	memset( ctx_p->tweak_state, 0, SYMM_THREEFISH512_TWEAK_BYTES ); \
	MODIFY_TWEAK_FLAGS_ (ctx_p, |=, (SYMM_UBI512_TWEAK_FIRST_BIT | init_bitwise_or))

void
symm_ubi512_chain_config (Symm_UBI512 * SHIM_RESTRICT ctx,
			  uint64_t const              num_out_bits)
{
	INIT_TWEAK_ (ctx, (SYMM_UBI512_TWEAK_LAST_BIT | SYMM_UBI512_TYPEMASK_CFG));
	MODIFY_TWEAK_POSITION_ (ctx, =, 32);
	static uint8_t const First_5_Bytes [5] = {
		0x53, 0x48, 0x41, 0x33, /* Schema identifier "SHA3" */
		0x01			/* Version number */
	};
	memcpy( ctx->msg_state,
		First_5_Bytes,
		sizeof(First_5_Bytes) );
	memset( ctx->msg_state + sizeof(First_5_Bytes),
		0,
		sizeof(ctx->msg_state) - sizeof(First_5_Bytes) );
	memcpy( ctx->msg_state + 8,
		&num_out_bits,
		sizeof(num_out_bits) );
	REKEY_CIPHER_XOR_ (ctx);
}
void
symm_ubi512_chain_native_output (Symm_UBI512 * SHIM_RESTRICT ctx,
			         uint8_t *     SHIM_RESTRICT output)
{
	INIT_TWEAK_ (ctx, (SYMM_UBI512_TWEAK_LAST_BIT | SYMM_UBI512_TYPEMASK_OUT));
	MODIFY_TWEAK_POSITION_ (ctx, =, sizeof(uint64_t));
	memset( ctx->msg_state, 0, sizeof(ctx->msg_state) );
	REKEY_CIPHER_XOR_ (ctx);
	memcpy( output, ctx->key_state, SYMM_THREEFISH512_BLOCK_BYTES );
}
void
symm_ubi512_chain_message (Symm_UBI512 *   SHIM_RESTRICT ctx,
			   uint8_t const * SHIM_RESTRICT input,
			   uint64_t                      num_in_bytes)
{
	INIT_TWEAK_ (ctx, SYMM_UBI512_TYPEMASK_MSG);
	if( num_in_bytes <= SYMM_THREEFISH512_BLOCK_BYTES ) {
		MODIFY_TWEAK_FLAGS_    (ctx, |=, SYMM_UBI512_TWEAK_LAST_BIT);
		MODIFY_TWEAK_POSITION_ (ctx,  =, num_in_bytes);
		memcpy( ctx->msg_state, input, num_in_bytes );
		memset( (ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes) );
		REKEY_CIPHER_XOR_ (ctx);
		return;
	}
	MODIFY_TWEAK_POSITION_ (ctx, =, SYMM_THREEFISH512_BLOCK_BYTES);
	memcpy( ctx->msg_state, input, SYMM_THREEFISH512_BLOCK_BYTES );
	REKEY_CIPHER_XOR_ (ctx);
	MODIFY_TWEAK_FLAGS_ (ctx, &=, SYMM_UBI512_TWEAK_FIRST_MASK);
	num_in_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
	input        += SYMM_THREEFISH512_BLOCK_BYTES;
	while( num_in_bytes > SYMM_THREEFISH512_BLOCK_BYTES ) {
		MODIFY_TWEAK_POSITION_ (ctx, +=, SYMM_THREEFISH512_BLOCK_BYTES);
		memcpy( ctx->msg_state, input, SYMM_THREEFISH512_BLOCK_BYTES );
		REKEY_CIPHER_XOR_ (ctx);
		num_in_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
		input        += SYMM_THREEFISH512_BLOCK_BYTES;
	}
	MODIFY_TWEAK_FLAGS_    (ctx, |=, SYMM_UBI512_TWEAK_LAST_BIT);
	MODIFY_TWEAK_POSITION_ (ctx, +=, num_in_bytes);
	memcpy( ctx->msg_state, input, num_in_bytes );
	memset( (ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes) );
	REKEY_CIPHER_XOR_ (ctx);
}
void
symm_ubi512_chain_output (Symm_UBI512 * SHIM_RESTRICT ctx,
			  uint8_t *     SHIM_RESTRICT output,
			  uint64_t                    num_out_bytes)
{
	/* We're doing at least one block. */
	INIT_TWEAK_ (ctx, SYMM_UBI512_TYPEMASK_OUT);
	memset( ctx->msg_state, 0, sizeof(ctx->msg_state) );
	MODIFY_TWEAK_POSITION_ (ctx, =, sizeof(uint64_t));
	if( num_out_bytes <= SYMM_THREEFISH512_BLOCK_BYTES ) {
		/* We're only doing one block. */
		MODIFY_TWEAK_FLAGS_ (ctx, |=, SYMM_UBI512_TWEAK_LAST_BIT);
		REKEY_CIPHER_XOR_ (ctx);
		memcpy( output, ctx->key_state, num_out_bytes );
		return;
	}
	/* This first block is guaranteed to not be the last. */
	REKEY_CIPHER_XOR_ (ctx);
	MODIFY_TWEAK_FLAGS_ (ctx, &=, SYMM_UBI512_TWEAK_FIRST_MASK);
	memcpy( output, ctx->key_state, SYMM_THREEFISH512_BLOCK_BYTES );
	SHIM_BIT_CAST_OP (ctx->msg_state, uint64_t, temp, ++temp);
	num_out_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
	output        += SYMM_THREEFISH512_BLOCK_BYTES;
	while( num_out_bytes > SYMM_THREEFISH512_BLOCK_BYTES ) {
		/* While there is still more than one block left, the block cannot be the last block. */
		MODIFY_TWEAK_POSITION_ (ctx, +=, sizeof(uint64_t));
		REKEY_CIPHER_XOR_ (ctx);
		memcpy( output, ctx->key_state, SYMM_THREEFISH512_BLOCK_BYTES );
		SHIM_BIT_CAST_OP (ctx->msg_state, uint64_t, temp, ++temp);
		num_out_bytes -= SYMM_THREEFISH512_BLOCK_BYTES;
		output        += SYMM_THREEFISH512_BLOCK_BYTES;
	}
	/* This is the last block. */
	MODIFY_TWEAK_FLAGS_ (ctx, |=, SYMM_UBI512_TWEAK_LAST_BIT);
	MODIFY_TWEAK_POSITION_ (ctx, +=, sizeof(uint64_t));
	REKEY_CIPHER_XOR_ (ctx);
	memcpy( output, ctx->key_state, num_out_bytes );
}
void
symm_ubi512_chain_key (Symm_UBI512 *   SHIM_RESTRICT ctx,
		       uint8_t const * SHIM_RESTRICT input)
{
	INIT_TWEAK_ (ctx, (SYMM_UBI512_TWEAK_LAST_BIT | SYMM_UBI512_TYPEMASK_KEY));
	MODIFY_TWEAK_POSITION_ (ctx, =, SYMM_THREEFISH512_BLOCK_BYTES);
	memcpy( ctx->msg_state, input, SYMM_THREEFISH512_BLOCK_BYTES );
	REKEY_CIPHER_XOR_ (ctx);
}

