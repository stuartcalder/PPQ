#include "threefish512.h"

#define R_(ptr) ptr BASE_RESTRICT
#define INIT_KEYSCHEDULE_(key, twk) \
	do { \
		key[SKC_THREEFISH512_BLOCK_BYTES] = SKC_THREEFISH512_CONSTANT_240 ^ \
						    key[0] ^ key[1] ^ key[2] ^ key[3] ^ \
						    key[4] ^ key[5] ^ key[6] ^ key[7]; \
		twk[2] = twk[0] ^ twk[1]; \
	} while (0)

typedef Skc_Threefish512_Static  Static_t;
typedef Skc_Threefish512_Dynamic Dynamic_t;
typedef Skc_Threefish512_CTR     Ctr_t;

void Skc_Threefish512_Static_init (R_(Static_t* const) ctx, R_(uint64_t* const) key, R_(uint64_t* const) twk) {
#define MAKE_WORD_(key, subkey, i) key[((subkey) + i) % (SKC_THREEFISH512_BLOCK_WORDS + 1)]
#define SET_WORD_(subkey, i) ctx->key_schedule[((subkey) * SKC_THREEFISH512_BLOCK_WORDS) + i] = MAKE_WORD_(key, (subkey), i)
#define MAKE_SUBKEY_(subkey) do { \
		SET_WORD_(subkey, 0); \
		SET_WORD_(subkey, 1); \
		SET_WORD_(subkey, 2); \
		SET_WORD_(subkey, 3); \
		SET_WORD_(subkey, 4); \
		SET_WORD_(subkey, 5) + twk[(subkey) % 3]; \
		SET_WORD_(subkey, 6) + twk[((subkey) + 1) % 3]; \
		SET_WORD_(subkey, 7) + (subkey); \
	} while (0)
#define MAKE_4_SUBKEYS_(start_skey) do { \
		MAKE_SUBKEY_(start_skey); \
		MAKE_SUBKEY_(start_skey + 1); \
		MAKE_SUBKEY_(start_skey + 2); \
		MAKE_SUBKEY_(start_skey + 3); \
	} while (0)

	INIT_KEYSCHEDULE_(key, twk);
	MAKE_4_SUBKEYS_(0);
	MAKE_4_SUBKEYS_(4);
	MAKE_4_SUBKEYS_(8);
	MAKE_4_SUBKEYS_(12);
	MAKE_SUBKEY_(16);
	MAKE_SUBKEY_(17);
	MAKE_SUBKEY_(18);
}

static const int ROTATE_ [8][4] = {
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44,  9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{ 8, 35, 56, 22}
};

void Skc_Threefish512_Static_encipher (R_(Static_t* const) ctx, uint8_t* const ctext, const uint8_t* const ptext) {
#define GET_ROT_(round, index) (ROTATE_[round % 8][index])
#define MIX_(w0, w1, round, index) do { \
		w0 += w1; \
		w1 = BASE_ROT_LEFT(w1, GET_ROT_(round, index), 64) ^ w0; \
	} while (0)
#define DO_MIX_(round, index) MIX_(ctx->state[index * 2], ctx->state[(index * 2) + 1], round, index);
#define SUBKEY_INDEX_(round) (round / 4)
#define SUBKEY_OFFSET_(round) (SUBKEY_INDEX_(round) * SKC_THREEFISH512_BLOCK_WORDS)
#define USE_SUBKEY_(op, round) do { \
		ctx->state[0] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 0)]; \
		ctx->state[1] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 1)]; \
		ctx->state[2] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 2)]; \
		ctx->state[3] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 3)]; \
		ctx->state[4] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 4)]; \
		ctx->state[5] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 5)]; \
		ctx->state[6] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 6)]; \
		ctx->state[7] op ctx->key_schedule[(SUBKEY_OFFSET_(round) + 7)]; \
	} while (0)
#define PERMUTE_ do { \
		uint64_t w0, w1; \
		w0 = ctx->state[6]; \
		ctx->state[6] = ctx->state[0]; \
		w1 = ctx->state[4]; \
		ctx->state[4] = w0; \
		w0 = ctx->state[2]; \
		ctx->state[2] = w1; \
		ctx->state[0] = w0; \
		w0 = ctx->state[3]; \
		ctx->state[3] = ctx->state[7]; \
		ctx->state[7] = w0; \
	} while (0)
#define MIX_PERM_(round) \
	DO_MIX_(round, 0); \
	DO_MIX_(round, 1); \
	DO_MIX_(round, 2); \
	DO_MIX_(round, 3); \
	PERMUTE_
#define ENC_ROUND_(round_start) do { \
		USE_SUBKEY_(+=, round_start); \
		MIX_PERM_(round_start); \
		MIX_PERM_((round_start + 1)); \
		MIX_PERM_((round_start + 2)); \
		MIX_PERM_((round_start + 3)); \
	} while (0)

	BASE_STATIC_ASSERT(sizeof(ctx->state) == SKC_THREEFISH512_BLOCK_BYTES, "State is one threefish512 block.");
	memcpy(ctx->state, ptext, sizeof(ctx->state));
	ENC_ROUND_(0);
	ENC_ROUND_(4);
	ENC_ROUND_(8);
	ENC_ROUND_(12);
	ENC_ROUND_(16);
	ENC_ROUND_(20);
	ENC_ROUND_(24);
	ENC_ROUND_(28);
	ENC_ROUND_(32);
	ENC_ROUND_(36);
	ENC_ROUND_(40);
	ENC_ROUND_(44);
	ENC_ROUND_(48);
	ENC_ROUND_(52);
	ENC_ROUND_(56);
	ENC_ROUND_(60);
	ENC_ROUND_(64);
	ENC_ROUND_(68);
	USE_SUBKEY_(+=, 72);
	memcpy(ctext, ctx->state, sizeof(ctx->state));
}

void Skc_Threefish512_Dynamic_init (R_(Dynamic_t* const) ctx, R_(uint64_t* const) key, R_(uint64_t* const) twk) {
	INIT_KEYSCHEDULE_(key, twk);
	ctx->extern_key = key;
	ctx->extern_tweak = twk;
}

void Skc_Threefish512_Dynamic_encipher (R_(Dynamic_t* const) ctx, uint8_t* const ctext, const uint8_t* const ptext) {
#undef USE_SUBKEY_
#define USE_SUBKEY_(op, round) do { \
		ctx->state[0] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 0)); \
		ctx->state[1] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 1)); \
		ctx->state[2] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 2)); \
		ctx->state[3] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 3)); \
		ctx->state[4] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 4)); \
		ctx->state[5] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 5) + ctx->extern_tweak[SUBKEY_INDEX_(round) % 3]); \
		ctx->state[6] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 6) + ctx->extern_tweak[(SUBKEY_INDEX_(round) + 1) % 3]); \
		ctx->state[7] op (MAKE_WORD_(ctx->extern_key, SUBKEY_INDEX_(round), 7) + SUBKEY_INDEX_(round)); \
	} while (0)
	memcpy(ctx->state, ptext, sizeof(ctx->state));
	ENC_ROUND_(0);
	ENC_ROUND_(4);
	ENC_ROUND_(8);
	ENC_ROUND_(12);
	ENC_ROUND_(16);
	ENC_ROUND_(20);
	ENC_ROUND_(24);
	ENC_ROUND_(28);
	ENC_ROUND_(32);
	ENC_ROUND_(36);
	ENC_ROUND_(40);
	ENC_ROUND_(44);
	ENC_ROUND_(48);
	ENC_ROUND_(52);
	ENC_ROUND_(56);
	ENC_ROUND_(60);
	ENC_ROUND_(64);
	ENC_ROUND_(68);
	USE_SUBKEY_(+=, 72);
	memcpy(ctext, ctx->state, sizeof(ctx->state));
}

void Skc_Threefish512_CTR_init (R_(Ctr_t* const) ctx, R_(const uint8_t* const) init_vec) {
	uint8_t* p = ctx->keystream + 8;
	memset(p, 0, (SKC_THREEFISH512_CTR_IV_BYTES - 8));
	p = ctx->keystream + SKC_THREEFISH512_CTR_IV_BYTES;
	memcpy(p, init_vec, SKC_THREEFISH512_CTR_IV_BYTES);
}

void Skc_Threefish512_CTR_xor_keystream (R_(Ctr_t* const) ctx, uint8_t* output, const uint8_t* input, uint64_t input_size, uint64_t start_byte) {
#define INC_U64_(keystream) BASE_BIT_CAST_OP(keystream, uint64_t, tmp, ++tmp)
	if (!start_byte)
		memset(ctx->keystream, 0, sizeof(uint64_t));
	else {
		uint64_t starting_block = start_byte / SKC_THREEFISH512_BLOCK_BYTES;
		int      offset         = start_byte % SKC_THREEFISH512_BLOCK_BYTES;
		int      bytes          = SKC_THREEFISH512_BLOCK_BYTES - offset;
		memcpy(ctx->keystream, &starting_block, sizeof(starting_block));
		Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
		INC_U64_(ctx->keystream);
		uint8_t* off = ctx->buffer + offset;
		int left;
		if (input_size >= (uint64_t)bytes)
			left = bytes;
		else
			left = (int)input_size;
		for (int i = 0; i < left; ++i)
			off[i] ^= input[i];
		memcpy(output, off, left);
		input      += left;
		output     += left;
		input_size -= left;
	}
	while (input_size >= SKC_THREEFISH512_BLOCK_BYTES) {
		Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
		INC_U64_(ctx->keystream);
		Base_xor_64(ctx->buffer, input);
		memcpy(output, ctx->buffer, SKC_THREEFISH512_BLOCK_BYTES);
		input      += SKC_THREEFISH512_BLOCK_BYTES;
		output     += SKC_THREEFISH512_BLOCK_BYTES;
		input_size -= SKC_THREEFISH512_BLOCK_BYTES;
	}
	if (input_size) {
		Skc_Threefish512_Static_encipher(&ctx->threefish512, ctx->buffer, ctx->keystream);
		for (int i = 0; i < (int)input_size; ++i)
			ctx->buffer[i] ^= input[i];
		memcpy(output, ctx->buffer, input_size);
	}
}
