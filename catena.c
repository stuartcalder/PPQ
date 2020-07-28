#include "catena.h"
#include <stdalign.h>
#include "skein512.h"

#define INDEX_HASH_WORD_(ptr, index) \
	(ptr + (index * SYMM_THREEFISH512_BLOCK_BYTES))
#define COPY_HASH_WORD_(dest, src) \
	memcpy( dest, src, SYMM_THREEFISH512_BLOCK_BYTES )
#define HASH_TWO_WORDS_(ctx, dest, src) \
	symm_skein512_hash_native( &ctx->ubi512_ctx, \
				   dest, \
				   src, \
				   (SYMM_THREEFISH512_BLOCK_BYTES * 2) )

SHIM_BEGIN_DECLS

static void
make_tweak_nophi_ (Symm_Catena * SHIM_RESTRICT ctx,
	           uint8_t const               lambda);
static void
make_tweak_usephi_ (Symm_Catena * SHIM_RESTRICT ctx,
	            uint8_t const               lambda);
static void
flap_nophi_ (Symm_Catena * SHIM_RESTRICT ctx,
             uint8_t const               garlic,
             uint8_t const               lambda);
static void
flap_usephi_ (Symm_Catena * SHIM_RESTRICT ctx,
              uint8_t const               garlic,
              uint8_t const               lambda);
static void
gamma_ (Symm_Catena * SHIM_RESTRICT ctx,
	uint8_t const               garlic);
static void
phi_ (Symm_Catena * SHIM_RESTRICT ctx,
      uint8_t const               garlic);

SHIM_END_DECLS

alignas(uint64_t) static uint8_t const No_Phi_Version_ID_Hash [64] = {
	UINT8_C (0x79), UINT8_C (0xb5), UINT8_C (0x79), UINT8_C (0x1e), UINT8_C (0x9a), UINT8_C (0xac), UINT8_C (0x02), UINT8_C (0x64),
	UINT8_C (0x2a), UINT8_C (0xaa), UINT8_C (0x99), UINT8_C (0x1b), UINT8_C (0xd5), UINT8_C (0x47), UINT8_C (0xed), UINT8_C (0x14),
	UINT8_C (0x74), UINT8_C (0x4d), UINT8_C (0x72), UINT8_C (0xbf), UINT8_C (0x13), UINT8_C (0x22), UINT8_C (0x54), UINT8_C (0xc9),
	UINT8_C (0xad), UINT8_C (0xd6), UINT8_C (0xb9), UINT8_C (0xbe), UINT8_C (0xe8), UINT8_C (0x70), UINT8_C (0x18), UINT8_C (0xe2),
	UINT8_C (0xaa), UINT8_C (0x51), UINT8_C (0x50), UINT8_C (0xe2), UINT8_C (0x1f), UINT8_C (0xcd), UINT8_C (0x90), UINT8_C (0x19),
	UINT8_C (0xb6), UINT8_C (0x1f), UINT8_C (0x0e), UINT8_C (0xc6), UINT8_C (0x05), UINT8_C (0x00), UINT8_C (0xd6), UINT8_C (0xed),
	UINT8_C (0x7c), UINT8_C (0xf2), UINT8_C (0x03), UINT8_C (0x53), UINT8_C (0xfd), UINT8_C (0x42), UINT8_C (0xa5), UINT8_C (0xa3),
	UINT8_C (0x7a), UINT8_C (0x0e), UINT8_C (0xbb), UINT8_C (0xb4), UINT8_C (0xa7), UINT8_C (0xeb), UINT8_C (0xdb), UINT8_C (0xab)
};
alignas(uint64_t) static uint8_t const Use_Phi_Version_ID_Hash [64] = {
	UINT8_C (0x1f), UINT8_C (0x23), UINT8_C (0x89), UINT8_C (0x58), UINT8_C (0x4a), UINT8_C (0x4a), UINT8_C (0xbb), UINT8_C (0xa5),
	UINT8_C (0x9f), UINT8_C (0x09), UINT8_C (0xca), UINT8_C (0xd4), UINT8_C (0xef), UINT8_C (0xac), UINT8_C (0x43), UINT8_C (0x1d),
	UINT8_C (0xde), UINT8_C (0x9a), UINT8_C (0xb0), UINT8_C (0xf8), UINT8_C (0x69), UINT8_C (0xaa), UINT8_C (0x50), UINT8_C (0xf3),
	UINT8_C (0xed), UINT8_C (0xcc), UINT8_C (0xb4), UINT8_C (0x7d), UINT8_C (0x6d), UINT8_C (0x4f), UINT8_C (0x10), UINT8_C (0xb9),
	UINT8_C (0x8e), UINT8_C (0x6a), UINT8_C (0x68), UINT8_C (0xab), UINT8_C (0x6e), UINT8_C (0x53), UINT8_C (0xbc), UINT8_C (0xd6),
	UINT8_C (0xcf), UINT8_C (0xfc), UINT8_C (0xa7), UINT8_C (0x63), UINT8_C (0x94), UINT8_C (0x44), UINT8_C (0xbd), UINT8_C (0xc7),
	UINT8_C (0xb9), UINT8_C (0x6d), UINT8_C (0x09), UINT8_C (0xf5), UINT8_C (0x66), UINT8_C (0x31), UINT8_C (0xa3), UINT8_C (0xc5),
	UINT8_C (0xf3), UINT8_C (0x26), UINT8_C (0xeb), UINT8_C (0x6f), UINT8_C (0xa6), UINT8_C (0xac), UINT8_C (0xb0), UINT8_C (0xa6)
};


int SHIM_PUBLIC
symm_catena_nophi (Symm_Catena * SHIM_RESTRICT ctx,
		   uint8_t *     SHIM_RESTRICT output,
		   uint8_t *     SHIM_RESTRICT password,
		   int const                   password_size,
		   uint8_t const               g_low,
		   uint8_t const               g_high,
		   uint8_t const               lambda)
{
	/* Allocate the graph memory. Free it at the end of the procedure; return on alloc failure. */
	ctx->graph_memory = (uint8_t *)malloc( (UINT64_C (1) << g_high) * SYMM_THREEFISH512_BLOCK_BYTES );
	if( !ctx->graph_memory )
		return SYMM_CATENA_ALLOC_FAILURE;
	/* Construct the tweak; concatenation with password and salt and hash into the x buffer. */
	make_tweak_nophi_( ctx, lambda );
	memcpy( ctx->temp.tw_pw_salt + SYMM_CATENA_TWEAK_BYTES,
		password,
		password_size );
	shim_secure_zero( password, password_size );
	memcpy( ctx->temp.tw_pw_salt + SYMM_CATENA_TWEAK_BYTES + password_size,
		ctx->salt,
		sizeof(ctx->salt) );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->x_buffer,
				   ctx->temp.tw_pw_salt,
				   password_size + (SYMM_CATENA_TWEAK_BYTES + SYMM_CATENA_SALT_BYTES) );
	/* Initial flap; hash the x buffer into itself. */
	flap_nophi_( ctx, (g_low + 1) / 2, lambda );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->x_buffer,
				   ctx->x_buffer,
				   sizeof(ctx->x_buffer) );
	for( uint8_t g = g_low; g <= g_high; ++g ) {
	/* Iterating flap over incrementing garlics of g, hashing the output
	 * into the x buffer. */
		flap_nophi_( ctx, g, lambda );
		*(ctx->temp.catena) = g;
		COPY_HASH_WORD_ (ctx->temp.catena + sizeof(uint8_t),
				 ctx->x_buffer);
		symm_skein512_hash_native( &ctx->ubi512_ctx,
					   ctx->x_buffer,
					   ctx->temp.catena,
					   sizeof(ctx->temp.catena) );
	}
	/* Zero over and free the memory. Copy the buffer out of the procedure. */
	shim_secure_zero( ctx->graph_memory, (UINT64_C (1) << g_high) * SYMM_THREEFISH512_BLOCK_BYTES );
	free( ctx->graph_memory );
	COPY_HASH_WORD_ (output,
			 ctx->x_buffer);
	return SYMM_CATENA_SUCCESS;
}
int SHIM_PUBLIC
symm_catena_usephi (Symm_Catena * SHIM_RESTRICT ctx,
		    uint8_t *     SHIM_RESTRICT output,
		    uint8_t *     SHIM_RESTRICT password,
		    int const                   password_size,
		    uint8_t const               g_low,
		    uint8_t const               g_high,
		    uint8_t const               lambda)
{
	/* Allocate the graph memory. Free it at the end of the procedure; return on alloc failure. */
	ctx->graph_memory = (uint8_t *)malloc( (UINT64_C (1) << g_high) * SYMM_THREEFISH512_BLOCK_BYTES );
	if( !ctx->graph_memory )
		return SYMM_CATENA_ALLOC_FAILURE;
	/* Construct the tweak; concatenation with password and salt and hash into the x buffer. */
	make_tweak_usephi_( ctx, lambda );
	memcpy( ctx->temp.tw_pw_salt + SYMM_CATENA_TWEAK_BYTES,
		password,
		password_size );
	shim_secure_zero( password, password_size );
	memcpy( ctx->temp.tw_pw_salt + SYMM_CATENA_TWEAK_BYTES + password_size,
		ctx->salt,
		sizeof(ctx->salt) );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->x_buffer,
				   ctx->temp.tw_pw_salt,
				   password_size + (SYMM_CATENA_TWEAK_BYTES + SYMM_CATENA_SALT_BYTES) );
	/* Initial flap; hash the x buffer into itself. */
	flap_usephi_( ctx, (g_low + 1) / 2, lambda );
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   ctx->x_buffer,
				   ctx->x_buffer,
				   sizeof(ctx->x_buffer) );
	for( uint8_t g = g_low; g <= g_high; ++g ) {
	/* Iterating flap over incrementing garlics of g, hashing the output
	 * into the x buffer. */
		flap_usephi_( ctx, g, lambda );
		*(ctx->temp.catena) = g;
		COPY_HASH_WORD_ (ctx->temp.catena + sizeof(uint8_t),
				 ctx->x_buffer);
		symm_skein512_hash_native( &ctx->ubi512_ctx,
					   ctx->x_buffer,
					   ctx->temp.catena,
					   sizeof(ctx->temp.catena) );
	}
	/* Zero over and free the memory. Copy the buffer out of the procedure. */
	shim_secure_zero( ctx->graph_memory, ((UINT64_C (1) << g_high) * SYMM_THREEFISH512_BLOCK_BYTES) );
	free( ctx->graph_memory );
	COPY_HASH_WORD_ (output,
			 ctx->x_buffer);
	return SYMM_CATENA_SUCCESS;
}



void
make_tweak_nophi_ (Symm_Catena * SHIM_RESTRICT ctx,
		   uint8_t const               lambda)
{
	uint8_t *t = ctx->temp.tw_pw_salt;
	memcpy( t, No_Phi_Version_ID_Hash, sizeof(No_Phi_Version_ID_Hash) );
	t += SYMM_THREEFISH512_BLOCK_BYTES;
	(*t++) = SYMM_CATENA_DOMAIN_KDF;
	(*t++) = lambda;
	{
		uint16_t tmp = SYMM_THREEFISH512_BLOCK_BYTES;
		memcpy( t, &tmp, sizeof(tmp) );
		t += sizeof(tmp);
		tmp = (uint16_t)SYMM_CATENA_SALT_BYTES;
		memcpy( t, &tmp, sizeof(tmp) );
	}
}
void
make_tweak_usephi_ (Symm_Catena * SHIM_RESTRICT ctx,
		    uint8_t const               lambda)
{
	uint8_t *t = ctx->temp.tw_pw_salt;
	memcpy( t, Use_Phi_Version_ID_Hash, sizeof(Use_Phi_Version_ID_Hash) );
	t += SYMM_THREEFISH512_BLOCK_BYTES;
	(*t++) = SYMM_CATENA_DOMAIN_KDF;
	(*t++) = lambda;
	{
		uint16_t tmp = (uint16_t)(SYMM_THREEFISH512_BLOCK_BYTES);
		memcpy( t, &tmp, sizeof(tmp) );
		t += sizeof(tmp);
		tmp = (uint16_t)SYMM_CATENA_SALT_BYTES;
		memcpy( t, &tmp, sizeof(tmp) );
	}
}
void
flap_nophi_ (Symm_Catena * SHIM_RESTRICT ctx,
	     uint8_t const               garlic,
	     uint8_t const               lambda)
{
#define TEMP_MEM_	ctx->temp.flap
#define GRAPH_MEM_	ctx->graph_memory
#define X_MEM_		ctx->x_buffer
	alignas(uint64_t) static uint8_t const Config [SYMM_THREEFISH512_BLOCK_BYTES] = {
		UINT8_C (0x54), UINT8_C (0x5e), UINT8_C (0x7a), UINT8_C (0x4c), UINT8_C (0x78), UINT8_C (0x32), UINT8_C (0xaf), UINT8_C (0xdb),
		UINT8_C (0xc7), UINT8_C (0xab), UINT8_C (0x18), UINT8_C (0xd2), UINT8_C (0x87), UINT8_C (0xd9), UINT8_C (0xe6), UINT8_C (0x2d),
		UINT8_C (0x41), UINT8_C (0x08), UINT8_C (0x90), UINT8_C (0x3a), UINT8_C (0xcb), UINT8_C (0xa9), UINT8_C (0xa3), UINT8_C (0xae),
		UINT8_C (0x31), UINT8_C (0x08), UINT8_C (0xc7), UINT8_C (0xe4), UINT8_C (0x0e), UINT8_C (0x0e), UINT8_C (0x55), UINT8_C (0xa0),
		UINT8_C (0xc3), UINT8_C (0x9c), UINT8_C (0xa8), UINT8_C (0x5d), UINT8_C (0x6c), UINT8_C (0xd2), UINT8_C (0x46), UINT8_C (0x71),
		UINT8_C (0xba), UINT8_C (0x1b), UINT8_C (0x58), UINT8_C (0x66), UINT8_C (0x31), UINT8_C (0xa3), UINT8_C (0xfd), UINT8_C (0x33),
		UINT8_C (0x87), UINT8_C (0x69), UINT8_C (0x83), UINT8_C (0x54), UINT8_C (0x3c), UINT8_C (0x17), UINT8_C (0x93), UINT8_C (0x02),
		UINT8_C (0xd7), UINT8_C (0x59), UINT8_C (0x94), UINT8_C (0x61), UINT8_C (0x00), UINT8_C (0xb8), UINT8_C (0xb8), UINT8_C (0x07)
	};
	memcpy( ctx->ubi512_ctx.key_state,
		Config,
		sizeof(Config) );
	symm_ubi512_chain_message( &ctx->ubi512_ctx,
				   INDEX_HASH_WORD_ (X_MEM_, 0),
				   SYMM_THREEFISH512_BLOCK_BYTES );
	symm_ubi512_chain_output( &ctx->ubi512_ctx,
				  INDEX_HASH_WORD_ (TEMP_MEM_, 0),
				  (SYMM_THREEFISH512_BLOCK_BYTES * 2) );
	HASH_TWO_WORDS_ (ctx,
			 INDEX_HASH_WORD_ (TEMP_MEM_, 1),
			 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 2),
			 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	HASH_TWO_WORDS_ (ctx,
			 INDEX_HASH_WORD_ (TEMP_MEM_,  0),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  1));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 0),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  1));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 1),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
	uint64_t const max_hash_index = (UINT64_C (1) << garlic) - 1;
	if( max_hash_index > 1 ) {
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_,  2),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 2),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_,  1),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_,  2),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  1));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 3),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
	}
	for( uint64_t i = 4; i <= max_hash_index; ++i ) {
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_,  2),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_,  1),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_,  0),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, i),
				 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
	}
	gamma_( ctx, garlic );
	symm_graph_hash( &ctx->ubi512_ctx,
			 ctx->temp.mhf,
			 GRAPH_MEM_,
			 garlic,
			 lambda );
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (X_MEM_, 0),
			 INDEX_HASH_WORD_ (GRAPH_MEM_, max_hash_index));
#undef X_MEM_
#undef GRAPH_MEM_
#undef TEMP_MEM_
}

void
flap_usephi_ (Symm_Catena * SHIM_RESTRICT ctx,
	      uint8_t const               garlic,
	      uint8_t const               lambda)
{
#define TEMP_MEM_	ctx->temp.flap
#define GRAPH_MEM_	ctx->graph_memory
#define X_MEM_		ctx->x_buffer
	alignas(uint64_t) static uint8_t const Config [SYMM_THREEFISH512_BLOCK_BYTES] = {
		0x54,0x5e,0x7a,0x4c,0x78,0x32,0xaf,0xdb,
		0xc7,0xab,0x18,0xd2,0x87,0xd9,0xe6,0x2d,
		0x41,0x08,0x90,0x3a,0xcb,0xa9,0xa3,0xae,
		0x31,0x08,0xc7,0xe4,0x0e,0x0e,0x55,0xa0,
		0xc3,0x9c,0xa8,0x5d,0x6c,0xd2,0x46,0x71,
		0xba,0x1b,0x58,0x66,0x31,0xa3,0xfd,0x33,
		0x87,0x69,0x83,0x54,0x3c,0x17,0x93,0x02,
		0xd7,0x59,0x94,0x61,0x00,0xb8,0xb8,0x07
	};
	memcpy( ctx->ubi512_ctx.key_state,
		Config,
		sizeof(Config) );
	symm_ubi512_chain_message( &ctx->ubi512_ctx,
				   INDEX_HASH_WORD_ (X_MEM_, 0),
				   SYMM_THREEFISH512_BLOCK_BYTES );
	symm_ubi512_chain_output( &ctx->ubi512_ctx,
				  INDEX_HASH_WORD_ (TEMP_MEM_, 0),
				  (SYMM_THREEFISH512_BLOCK_BYTES * 2) );
	HASH_TWO_WORDS_ (ctx,
			 INDEX_HASH_WORD_ (TEMP_MEM_, 1),
			 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 2),
			 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	HASH_TWO_WORDS_ (ctx,
			 INDEX_HASH_WORD_ (TEMP_MEM_,  0),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  1));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 0),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  1));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 1),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
	uint64_t const max_hash_index = (UINT64_C (1) << garlic) - 1;
	if( max_hash_index > 1 ) {
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_, 2),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 2),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 1),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 2),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 1));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, 3),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	}
	for( uint64_t i = 4; i <= max_hash_index; ++i ) {
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (TEMP_MEM_, 2),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 1),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 0),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 2));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (GRAPH_MEM_, i),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	}
	gamma_( ctx, garlic ); // todo?
	symm_graph_hash( &ctx->ubi512_ctx,
			 ctx->temp.mhf,
			 GRAPH_MEM_,
			 garlic,
			 lambda );
	phi_( ctx, garlic );
#undef X_MEM_
#undef GRAPH_MEM_
#undef TEMP_MEM_
}


void
gamma_ (Symm_Catena * SHIM_RESTRICT ctx,
	uint8_t const               garlic)
{
#define GRAPH_MEM_		ctx->graph_memory
#define TEMP_MEM_		ctx->temp.gamma
#define SALT_AND_GARLIC_BYTES_	(sizeof(ctx->salt) + sizeof(uint8_t))
#define RNG_OUTPUT_SIZE_	(SYMM_THREEFISH512_BLOCK_BYTES + (sizeof(uint64_t) * 2))
#define J1_OFFSET_		SYMM_THREEFISH512_BLOCK_BYTES
#define J2_OFFSET_		(J1_OFFSET_ + sizeof(uint64_t))
	memcpy( TEMP_MEM_.rng,
		ctx->salt,
		sizeof(ctx->salt) );
	*(TEMP_MEM_.rng + sizeof(ctx->salt)) = garlic;
	symm_skein512_hash_native( &ctx->ubi512_ctx,
				   TEMP_MEM_.rng,
				   TEMP_MEM_.rng,
				   SALT_AND_GARLIC_BYTES_ );
	uint64_t const count = (UINT64_C (1) << (((3 * garlic) + 3) / 4));
	int const right_shift_amt = 64 - garlic;
	for( uint64_t i = 0; i < count; ++i ) {
		alignas(uint64_t) static uint8_t const Config [64] = {
			0xf0, 0xef, 0xcb, 0xca, 0xbf, 0xd0, 0x04, 0x7b,
			0xc0, 0x5d, 0x3e, 0x3a, 0x1d, 0x53, 0xe4, 0x9f,
			0x07, 0xbf, 0x4f, 0xf5, 0xce, 0x67, 0x53, 0x53,
			0x9f, 0x0e, 0xf7, 0xfb, 0x22, 0xe6, 0xf4, 0xc3,
			0x74, 0xcc, 0xb9, 0xed, 0xc0, 0x50, 0x23, 0x81,
			0x65, 0x27, 0x7a, 0xc2, 0xb2, 0xea, 0xfb, 0x96,
			0xcb, 0x91, 0xe2, 0x97, 0x59, 0x94, 0x1f, 0x6d,
			0x51, 0xc3, 0x9f, 0xe5, 0x27, 0x31, 0xd1, 0xc5
		};
		memcpy( ctx->ubi512_ctx.key_state,
			Config,
			sizeof(Config) );
		symm_ubi512_chain_message( &ctx->ubi512_ctx,
					   TEMP_MEM_.rng,
					   SYMM_THREEFISH512_BLOCK_BYTES );
		symm_ubi512_chain_output( &ctx->ubi512_ctx,
					  TEMP_MEM_.rng,
					  RNG_OUTPUT_SIZE_ );
		uint64_t j1, j2;
		{
			memcpy( &j1, TEMP_MEM_.rng + J1_OFFSET_, sizeof(j1) );
			j1 >>= right_shift_amt;
			memcpy( &j2, TEMP_MEM_.rng + J2_OFFSET_, sizeof(j2) );
			j2 >>= right_shift_amt;
		}
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_.word_buf, 0),
				 INDEX_HASH_WORD_ (GRAPH_MEM_,        j1));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_.word_buf, 1),
				 INDEX_HASH_WORD_ (GRAPH_MEM_,        j2));
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (GRAPH_MEM_, j1),
				 INDEX_HASH_WORD_ (TEMP_MEM_.word_buf, 0));
	}
#undef J2_OFFSET_
#undef J1_OFFSET_
#undef RNG_OUTPUT_SIZE_
#undef SALT_AND_GARLIC_BYTES_
#undef TEMP_MEM_
#undef GRAPH_MEM_
}

void
phi_ (Symm_Catena * SHIM_RESTRICT ctx,
      uint8_t const               garlic)
{
#define GRAPH_MEM_ ctx->graph_memory
#define TEMP_MEM_  ctx->temp.phi
#define X_MEM_     ctx->x_buffer

	uint64_t const last_word_index = (UINT64_C (1) << garlic) - 1;
	int const right_shift_amt = 64 - garlic;
	uint64_t j;
	{
		memcpy( &j,
			INDEX_HASH_WORD_ (GRAPH_MEM_, last_word_index),
			sizeof(j) );
		j >>= right_shift_amt;
	}
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 0),
			 INDEX_HASH_WORD_ (GRAPH_MEM_, last_word_index));
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_, 1),
			 INDEX_HASH_WORD_ (GRAPH_MEM_, j));
	HASH_TWO_WORDS_ (ctx,
			 INDEX_HASH_WORD_ (GRAPH_MEM_, 0),
			 INDEX_HASH_WORD_ (TEMP_MEM_,  0));
	for( uint64_t i = 1; i <= last_word_index; ++i ) {
		{
			memcpy( &j,
				INDEX_HASH_WORD_ (GRAPH_MEM_, (i - 1)),
				sizeof(j) );
			j >>= right_shift_amt;
		}
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_ ,      0 ),
				 INDEX_HASH_WORD_ (GRAPH_MEM_, (i - 1)));
		COPY_HASH_WORD_ (INDEX_HASH_WORD_ (TEMP_MEM_ ,      1 ),
				 INDEX_HASH_WORD_ (GRAPH_MEM_,      j ));
		HASH_TWO_WORDS_ (ctx,
				 INDEX_HASH_WORD_ (GRAPH_MEM_, i),
				 INDEX_HASH_WORD_ (TEMP_MEM_, 0));
	}
	COPY_HASH_WORD_ (INDEX_HASH_WORD_ (X_MEM_, 0),
			 INDEX_HASH_WORD_ (GRAPH_MEM_, last_word_index));
#undef X_MEM_
#undef TEMP_MEM_
#undef GRAPH_MEM_
}
