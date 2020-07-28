#include "threefish512.h"

static inline void init_keyschedule_ (uint64_t * SHIM_RESTRICT key,
				      uint64_t * SHIM_RESTRICT twk)
{
	key[ SYMM_THREEFISH512_BLOCK_WORDS ] = SYMM_THREEFISH512_CONSTANT_240 ^
						key[ 0 ] ^ key[ 1 ] ^ key[ 2 ] ^ key[ 3 ] ^
						key[ 4 ] ^ key[ 5 ] ^ key[ 6 ] ^ key[ 7 ];
	twk[ 2 ] = twk[ 0 ] ^ twk[ 1 ];
}

void SHIM_PUBLIC
symm_threefish512_stored_rekey (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
			        uint64_t *                 SHIM_RESTRICT key,
			        uint64_t *                 SHIM_RESTRICT twk)
{
#define MAKE_WORD_(key_v_buf, subkey, i) \
	key_v_buf[ (subkey + i) % (SYMM_THREEFISH512_BLOCK_WORDS + 1) ]
#define SET_WORD_(subkey, i) \
	ctx->key_schedule[ (subkey * SYMM_THREEFISH512_BLOCK_WORDS) + i ] = MAKE_WORD_ (key, subkey, i)
#define MAKE_SUBKEY_(subkey) \
	SHIM_MACRO_SHIELD \
		SET_WORD_ (subkey, 0); \
		SET_WORD_ (subkey, 1); \
		SET_WORD_ (subkey, 2); \
		SET_WORD_ (subkey, 3); \
		SET_WORD_ (subkey, 4); \
		SET_WORD_ (subkey, 5) + twk[ subkey % 3 ]; \
		SET_WORD_ (subkey, 6) + twk[ (subkey + 1) % 3 ]; \
		SET_WORD_ (subkey, 7) + subkey; \
	SHIM_MACRO_SHIELD_EXIT
#define MAKE_4_SUBKEYS_(start_subkey) \
	SHIM_MACRO_SHIELD \
		MAKE_SUBKEY_ (start_subkey); \
		MAKE_SUBKEY_ (start_subkey + 1); \
		MAKE_SUBKEY_ (start_subkey + 2); \
		MAKE_SUBKEY_ (start_subkey + 3); \
	SHIM_MACRO_SHIELD_EXIT

	init_keyschedule_( key, twk );

	MAKE_4_SUBKEYS_  (0);
	MAKE_4_SUBKEYS_  (4);
	MAKE_4_SUBKEYS_  (8);
	MAKE_4_SUBKEYS_ (12);
	MAKE_SUBKEY_    (16);
	MAKE_SUBKEY_    (17);
	MAKE_SUBKEY_    (18);
}

static int const Rotate_Constants [8][4] = {
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44,  9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{ 8, 35, 56, 22}
};

void SHIM_PUBLIC
symm_threefish512_stored_cipher (Symm_Threefish512_Stored * SHIM_RESTRICT ctx,
				 uint8_t *                  SHIM_RESTRICT ctext,
				 uint8_t const *            SHIM_RESTRICT ptext)
{
#define ROTATE_CONST_(round, index) \
	(Rotate_Constants[ round % 8 ][ index ])
#define MIX_(word_0, word_1, round, index) \
	SHIM_MACRO_SHIELD \
		word_0 += word_1; \
		word_1 = SHIM_ROT_LEFT (word_1, ROTATE_CONST_ (round, index), 64) ^ word_0; \
	SHIM_MACRO_SHIELD_EXIT
#define DO_MIX_(round, index) \
	MIX_ (ctx->state[ index * 2 ], ctx->state[ (index * 2) + 1 ], round, index);
#define SUBKEY_INDEX_(round) \
	(round / 4)
#define SUBKEY_OFFSET_(round) \
	(SUBKEY_INDEX_ (round) * SYMM_THREEFISH512_BLOCK_WORDS)
#define USE_SUBKEY_(operation, round) \
	SHIM_MACRO_SHIELD \
		ctx->state[ 0 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 0) ]; \
		ctx->state[ 1 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 1) ]; \
		ctx->state[ 2 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 2) ]; \
		ctx->state[ 3 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 3) ]; \
		ctx->state[ 4 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 4) ]; \
		ctx->state[ 5 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 5) ]; \
		ctx->state[ 6 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 6) ]; \
		ctx->state[ 7 ] operation ctx->key_schedule[ (SUBKEY_OFFSET_ (round) + 7) ]; \
	SHIM_MACRO_SHIELD_EXIT
#define PERMUTE_ \
	SHIM_MACRO_SHIELD \
		uint64_t w0, w1; \
		w0 = ctx->state[ 6 ]; \
		ctx->state[ 6 ] = ctx->state[ 0 ]; \
		w1 = ctx->state[ 4 ]; \
		ctx->state[ 4 ] = w0; \
		w0 = ctx->state[ 2 ]; \
		ctx->state[ 2 ] = w1; \
		ctx->state[ 0 ] = w0; \
		w0 = ctx->state[ 3 ]; \
		ctx->state[ 3 ] = ctx->state[ 7 ]; \
		ctx->state[ 7 ] = w0; \
	SHIM_MACRO_SHIELD_EXIT

#define MIX_PERM_(round) \
	DO_MIX_ (round, 0); \
	DO_MIX_ (round, 1); \
	DO_MIX_ (round, 2); \
	DO_MIX_ (round, 3); \
	PERMUTE_

#define ENC_ROUND_(round_start) \
	SHIM_MACRO_SHIELD \
		USE_SUBKEY_ (+=, round_start); \
		MIX_PERM_ (round_start); \
		MIX_PERM_ ((round_start + 1)); \
		MIX_PERM_ ((round_start + 2)); \
		MIX_PERM_ ((round_start + 3)); \
	SHIM_MACRO_SHIELD_EXIT

	static_assert (sizeof(ctx->state) == SYMM_THREEFISH512_BLOCK_BYTES, "The state is one Threefish512 block.");
	memcpy( ctx->state, ptext, sizeof(ctx->state) );
	ENC_ROUND_ (0);
	ENC_ROUND_ (4);
	ENC_ROUND_ (8);
	ENC_ROUND_ (12);
	ENC_ROUND_ (16);
	ENC_ROUND_ (20);
	ENC_ROUND_ (24);
	ENC_ROUND_ (28);
	ENC_ROUND_ (32);
	ENC_ROUND_ (36);
	ENC_ROUND_ (40);
	ENC_ROUND_ (44);
	ENC_ROUND_ (48);
	ENC_ROUND_ (52);
	ENC_ROUND_ (56);
	ENC_ROUND_ (60);
	ENC_ROUND_ (64);
	ENC_ROUND_ (68);
	USE_SUBKEY_ (+=, 72);
	memcpy( ctext, ctx->state, sizeof(ctx->state) );

}// ~ symm_threefish512_stored_cipher(...)

void SHIM_PUBLIC
symm_threefish512_ondemand_rekey (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				  uint64_t *                    SHIM_RESTRICT key,
				  uint64_t *                    SHIM_RESTRICT twk)
{
	init_keyschedule_( key, twk );
	ctx->stored_key = key;
	ctx->stored_tweak = twk;
}// ~ symm_threefish512_ondemand_rekey(...)

void SHIM_PUBLIC
symm_threefish512_ondemand_cipher (Symm_Threefish512_On_Demand * SHIM_RESTRICT ctx,
				   uint8_t *                     SHIM_RESTRICT ctext,
				   uint8_t const *               SHIM_RESTRICT ptext)
{
#undef  USE_SUBKEY_
#define USE_SUBKEY_(operation, round) \
	SHIM_MACRO_SHIELD \
		ctx->state[ 0 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 0)); \
		ctx->state[ 1 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 1)); \
		ctx->state[ 2 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 2)); \
		ctx->state[ 3 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 3)); \
		ctx->state[ 4 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 4)); \
		ctx->state[ 5 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 5) + ctx->stored_tweak[ (SUBKEY_INDEX_ (round) % 3) ]); \
		ctx->state[ 6 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 6) + ctx->stored_tweak[ (SUBKEY_INDEX_ (round) + 1) % 3 ]); \
		ctx->state[ 7 ] operation (MAKE_WORD_ (ctx->stored_key, SUBKEY_INDEX_ (round), 7) + SUBKEY_INDEX_ (round)); \
	SHIM_MACRO_SHIELD_EXIT

	static_assert (sizeof(ctx->state) == SYMM_THREEFISH512_BLOCK_BYTES, "The state is one Threefish512 block.");
	memcpy( ctx->state, ptext, sizeof(ctx->state) );
	ENC_ROUND_ (0);
	ENC_ROUND_ (4);
	ENC_ROUND_ (8);
	ENC_ROUND_ (12);
	ENC_ROUND_ (16);
	ENC_ROUND_ (20);
	ENC_ROUND_ (24);
	ENC_ROUND_ (28);
	ENC_ROUND_ (32);
	ENC_ROUND_ (36);
	ENC_ROUND_ (40);
	ENC_ROUND_ (44);
	ENC_ROUND_ (48);
	ENC_ROUND_ (52);
	ENC_ROUND_ (56);
	ENC_ROUND_ (60);
	ENC_ROUND_ (64);
	ENC_ROUND_ (68);
	USE_SUBKEY_ (+=, 72);
	memcpy( ctext, ctx->state, sizeof(ctx->state) );
}// ~ symm_threefish512_ondemand_cipher(...)


void SHIM_PUBLIC
symm_threefish512_ctr_setiv (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
			     uint8_t const *         SHIM_RESTRICT iv)
{
	memset( ctx->keystream + sizeof(uint64_t),
		0,
		SYMM_THREEFISH512_CTR_IV_BYTES - sizeof(uint64_t) );
	memcpy( ctx->keystream + SYMM_THREEFISH512_CTR_IV_BYTES,
		iv,
		SYMM_THREEFISH512_CTR_IV_BYTES );
}// ~ symm_threefish512_ctr_setiv(...)

void SHIM_PUBLIC
symm_threefish512_ctr_xorcrypt (Symm_Threefish512_CTR * SHIM_RESTRICT ctx,
				uint8_t *                             output,
				uint8_t const *                       input,
				uint64_t                              input_size,
				uint64_t                              starting_byte)
{
	if( starting_byte == 0 ) {
		memcpy( ctx->keystream, &starting_byte, sizeof(starting_byte) );
	} else {
		uint64_t starting_block = starting_byte / SYMM_THREEFISH512_BLOCK_BYTES;
		uint64_t offset         = starting_byte % SYMM_THREEFISH512_BLOCK_BYTES;
		uint64_t bytes          = SYMM_THREEFISH512_BLOCK_BYTES - offset;
		memcpy( ctx->keystream, &starting_block, sizeof(starting_block) );
		symm_threefish512_stored_cipher( &ctx->threefish_stored,
						 ctx->buffer,
						 ctx->keystream );
		SHIM_BIT_CAST_OP (ctx->keystream, uint64_t, tmp, ++tmp);
		uint8_t *offset_buffer = ctx->buffer + offset;
		uint64_t left;
		if( input_size >= bytes )
			left = bytes;
		else
			left = input_size;
		for( uint64_t i = 0; i < left; ++i )
			offset_buffer[ i ] ^= input[ i ];
		memcpy( output, offset_buffer, left );
		input      += left;
		output     += left;
		input_size -= left;
	}
	while( input_size >= SYMM_THREEFISH512_BLOCK_BYTES ) {
		symm_threefish512_stored_cipher( &ctx->threefish_stored,
						 ctx->buffer,
						 ctx->keystream );
		SHIM_BIT_CAST_OP (ctx->keystream, uint64_t, tmp, ++tmp);
		shim_xor_64( ctx->buffer, input );
		memcpy( output, ctx->buffer, SYMM_THREEFISH512_BLOCK_BYTES );
		input      += SYMM_THREEFISH512_BLOCK_BYTES;
		output     += SYMM_THREEFISH512_BLOCK_BYTES;
		input_size -= SYMM_THREEFISH512_BLOCK_BYTES;
	}
	if( input_size > 0 ) {
		symm_threefish512_stored_cipher( &ctx->threefish_stored,
						 ctx->buffer,
						 ctx->keystream );
		for( uint64_t i = 0; i < input_size; ++i )
			ctx->buffer[ i ] ^= input[ i ];
		memcpy( output, ctx->buffer, input_size );
	}
}// ~ symm_threefish512_ctr_xorcrypt(...)





