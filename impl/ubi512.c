#include <Base/mem.h>
#include "ubi512.h"

#define R_(ptr) ptr BASE_RESTRICT
#define INIT_ENCIPHER_XOR_(ctx) \
 Skc_UBI512_init_tf_ks(ctx); \
 Skc_Threefish512_Dynamic_encipher(&ctx->threefish512, ctx->key_state, ctx->msg_state); \
 Base_xor_64(ctx->key_state, ctx->msg_state)

#define MODIFY_TWEAK_FLAGS_(ctx, op, val) \
 ((uint8_t*)ctx->tweak_state)[SKC_THREEFISH512_TWEAK_BYTES - 1] op val

#define SET_TWEAK_POSITION_(ctx, val) \
 Base_store_le64(ctx->tweak_state, val)

#define MODIFY_TWEAK_POSITION_(ctx, op, val) \
  Base_store_le64(ctx->tweak_state, \
                  Base_load_le64(ctx->tweak_state) op val)

#define INIT_TWEAK_(ctx, init_bitwise_or) \
	memset(ctx->tweak_state, 0, SKC_THREEFISH512_TWEAK_BYTES); \
	MODIFY_TWEAK_FLAGS_(ctx, |=, (SKC_UBI512_TWEAK_FIRST_BIT | init_bitwise_or))

void Skc_UBI512_chain_config (R_(Skc_UBI512* const) ctx, const uint64_t num_out_bits) {
	INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_CFG));
	SET_TWEAK_POSITION_(ctx, 32);
	static const uint8_t init [SKC_THREEFISH512_BLOCK_BYTES] = {
		/* Schema identifier "SHA3" version 1. */
		0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	memcpy(ctx->msg_state, init, sizeof(init));
	Base_store_le64(ctx->msg_state + 8, num_out_bits);
	INIT_ENCIPHER_XOR_(ctx);
}
void Skc_UBI512_chain_native_output (R_(Skc_UBI512* const) ctx, R_(uint8_t*) output) {
	INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_OUT));
	SET_TWEAK_POSITION_(ctx, 8);
	memset(ctx->msg_state, 0, sizeof(ctx->msg_state));
	INIT_ENCIPHER_XOR_(ctx);
	memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
}
void Skc_UBI512_chain_message (R_(Skc_UBI512* const) ctx, R_(const uint8_t*) input, uint64_t num_in_bytes) {
	INIT_TWEAK_(ctx, SKC_UBI512_TYPEMASK_MSG);
	if (num_in_bytes <= SKC_THREEFISH512_BLOCK_BYTES) {
		MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
		SET_TWEAK_POSITION_(ctx, num_in_bytes);
		memcpy(ctx->msg_state, input, num_in_bytes);
		memset((ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes));
		INIT_ENCIPHER_XOR_(ctx);
		return;
	}
	SET_TWEAK_POSITION_(ctx, SKC_THREEFISH512_BLOCK_BYTES);
	memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
	INIT_ENCIPHER_XOR_(ctx);
	MODIFY_TWEAK_FLAGS_(ctx, &=, SKC_UBI512_TWEAK_FIRST_MASK);
	num_in_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
	input        += SKC_THREEFISH512_BLOCK_BYTES;
	while (num_in_bytes > SKC_THREEFISH512_BLOCK_BYTES) {
		MODIFY_TWEAK_POSITION_(ctx, +, SKC_THREEFISH512_BLOCK_BYTES);
		memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
		INIT_ENCIPHER_XOR_(ctx);
		num_in_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
		input        += SKC_THREEFISH512_BLOCK_BYTES;
	}
	MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
	MODIFY_TWEAK_POSITION_(ctx, +, num_in_bytes);
	memcpy(ctx->msg_state, input, num_in_bytes);
	memset((ctx->msg_state + num_in_bytes), 0, (sizeof(ctx->msg_state) - num_in_bytes));
	INIT_ENCIPHER_XOR_(ctx);
}
#define INC_U64_(ptr) Base_store_le64(ptr, Base_load_le64(ptr) + 1)

void Skc_UBI512_chain_output (R_(Skc_UBI512* const) ctx, R_(uint8_t*) output, uint64_t num_out_bytes) {
	/* We're doing at least one block. */
	INIT_TWEAK_(ctx, SKC_UBI512_TYPEMASK_OUT);
	memset(ctx->msg_state, 0, sizeof(ctx->msg_state));
	SET_TWEAK_POSITION_(ctx, 8);
	if (num_out_bytes <= SKC_THREEFISH512_BLOCK_BYTES) {
		MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
		INIT_ENCIPHER_XOR_(ctx);
		memcpy(output, ctx->key_state, num_out_bytes);
		return;
	}
	INIT_ENCIPHER_XOR_(ctx);
	MODIFY_TWEAK_FLAGS_(ctx, &=, SKC_UBI512_TWEAK_FIRST_MASK);
	memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
	INC_U64_(ctx->msg_state);
	num_out_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
	output        += SKC_THREEFISH512_BLOCK_BYTES;
	while (num_out_bytes > SKC_THREEFISH512_BLOCK_BYTES) {
		MODIFY_TWEAK_POSITION_(ctx, +, sizeof(uint64_t));
		INIT_ENCIPHER_XOR_(ctx);
		memcpy(output, ctx->key_state, SKC_THREEFISH512_BLOCK_BYTES);
		INC_U64_(ctx->msg_state);
		num_out_bytes -= SKC_THREEFISH512_BLOCK_BYTES;
		output        += SKC_THREEFISH512_BLOCK_BYTES;
	}
	MODIFY_TWEAK_FLAGS_(ctx, |=, SKC_UBI512_TWEAK_LAST_BIT);
	MODIFY_TWEAK_POSITION_(ctx, +, sizeof(uint64_t));
	INIT_ENCIPHER_XOR_(ctx);
	memcpy(output, ctx->key_state, num_out_bytes);
}
void Skc_UBI512_chain_key (R_(Skc_UBI512* const) ctx, R_(const uint8_t*) input) {
	INIT_TWEAK_(ctx, (SKC_UBI512_TWEAK_LAST_BIT | SKC_UBI512_TYPEMASK_KEY));
	SET_TWEAK_POSITION_(ctx, SKC_THREEFISH512_BLOCK_BYTES);
	memcpy(ctx->msg_state, input, SKC_THREEFISH512_BLOCK_BYTES);
	INIT_ENCIPHER_XOR_(ctx);
}
