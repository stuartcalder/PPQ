#ifndef SYMM_DRAGONFLY_V1_H
#define SYMM_DRAGONFLY_V1_H

/* Shim Headers */
#include <shim/macros.h>
#include <shim/print.h>
#include <shim/operations.h>
#include <shim/map.h>
/* Symm Headers */
#include "graph_hashing.h"
#include "catena.h"
#include "threefish512.h"
#include "csprng.h"
#include "common.h"

#define SYMM_DRAGONFLY_V1_ID				"SSC_DRAGONFLY_V1"
#define SYMM_DRAGONFLY_V1_BLOCK_BITS			512
#define SYMM_DRAGONFLY_V1_BLOCK_BYTES			(SYMM_DRAGONFLY_V1_BLOCK_BITS / CHAR_BIT)
#define SYMM_DRAGONFLY_V1_SALT_BITS			SYMM_CATENA_SALT_BITS
#define SYMM_DRAGONFLY_V1_SALT_BYTES			SYMM_CATENA_SALT_BYTES
#define SYMM_DRAGONFLY_V1_MAX_PASSWORD_BYTES		120
#define SYMM_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES	(17 + /*Sizeof dragonfly_v1 id*/ \
							 8  + /*header size*/ \
							 4  + /*g_low, g_high, use_phi, lambda*/ \
							 SYMM_THREEFISH512_TWEAK_BYTES + \
							 SYMM_DRAGONFLY_V1_SALT_BYTES + \
							 SYMM_THREEFISH512_CTR_IV_BYTES)
#define SYMM_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES	16
#define SYMM_DRAGONFLY_V1_TOTAL_HEADER_BYTES		(SYMM_DRAGONFLY_V1_PLAINTEXT_HEADER_BYTES + SYMM_DRAGONFLY_V1_CIPHERTEXT_HEADER_BYTES)
#define SYMM_DRAGONFLY_V1_MAC_BYTES			SYMM_THREEFISH512_BLOCK_BYTES
#define SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES	(SYMM_DRAGONFLY_V1_TOTAL_HEADER_BYTES + SYMM_DRAGONFLY_V1_MAC_BYTES)

alignas(uint64_t) static uint8_t const Symm_Dragonfly_V1_Safe_Metadata [SYMM_THREEFISH512_BLOCK_BYTES] = {
	0x79,0xb5,0x79,0x1e,0x9a,0xac,0x02,0x64,
	0x2a,0xaa,0x99,0x1b,0xd5,0x47,0xed,0x14,
	0x74,0x4d,0x72,0xbf,0x13,0x22,0x54,0xc9,
	0xad,0xd6,0xb9,0xbe,0xe8,0x70,0x18,0xe2,
	0xaa,0x51,0x50,0xe2,0x1f,0xcd,0x90,0x19,
	0xb6,0x1f,0x0e,0xc6,0x05,0x00,0xd6,0xed,
	0x7c,0xf2,0x03,0x53,0xfd,0x42,0xa5,0xa3,
	0x7a,0x0e,0xbb,0xb4,0xa7,0xeb,0xdb,0xab
};
alignas(uint64_t) static uint8_t const Symm_Dragonfly_V1_Strong_Metadata [SYMM_THREEFISH512_BLOCK_BYTES] = {
	0x1f,0x23,0x89,0x58,0x4a,0x4a,0xbb,0xa5,
	0x9f,0x09,0xca,0xd4,0xef,0xac,0x43,0x1d,
	0xde,0x9a,0xb0,0xf8,0x69,0xaa,0x50,0xf3,
	0xed,0xcc,0xb4,0x7d,0x6d,0x4f,0x10,0xb9,
	0x8e,0x6a,0x68,0xab,0x6e,0x53,0xbc,0xd6,
	0xcf,0xfc,0xa7,0x63,0x94,0x44,0xbd,0xc7,
	0xb9,0x6d,0x09,0xf5,0x66,0x31,0xa3,0xc5,
	0xf3,0x26,0xeb,0x6f,0xa6,0xac,0xb0,0xa6
};

typedef struct SHIM_PUBLIC {
	struct {
		Symm_Catena_Input         catena_input;
		Symm_Catena               catena;
		Symm_Threefish512_CTR     threefish512_ctr;
		Symm_UBI512               ubi512;
		uint64_t                  enc_key  [SYMM_THREEFISH512_EXTERNAL_KEY_WORDS];
		alignas(uint64_t) uint8_t auth_key [SYMM_THREEFISH512_BLOCK_BYTES];
		alignas(uint64_t) uint8_t hash_out [SYMM_THREEFISH512_BLOCK_BYTES * 2];
	} secret;
	struct {
		uint64_t                  tf_tweak    [SYMM_THREEFISH512_EXTERNAL_TWEAK_WORDS];
		alignas(uint64_t) uint8_t ctr_iv      [SYMM_THREEFISH512_CTR_IV_BYTES];
		alignas(uint64_t) uint8_t catena_salt [SYMM_CATENA_SALT_BYTES];
	} pub;
} Symm_Dragonfly_V1;
typedef struct SHIM_PUBLIC {
	Symm_Threefish512_CTR     threefish512_ctr;
	Symm_UBI512               ubi512;
	Symm_Catena               catena;
	uint64_t                  enc_key  [SYMM_THREEFISH512_EXTERNAL_KEY_WORDS];
	alignas(uint64_t) uint8_t auth_key [SYMM_THREEFISH512_BLOCK_BYTES];
	alignas(uint64_t) uint8_t hash_buf [SYMM_THREEFISH512_BLOCK_BYTES * 2];
	alignas(uint64_t) uint8_t mac      [SYMM_COMMON_MAC_BYTES];
	uint8_t                   password [SYMM_COMMON_PASSWORD_BUFFER_BYTES];
	int                       password_size;
} Symm_Dragonfly_V1_Decrypt;

SHIM_BEGIN_DECLS

void SHIM_PUBLIC
symm_dragonfly_v1_encrypt (Symm_Dragonfly_V1 *       SHIM_RESTRICT dragonfly_v1_ptr,
			   Shim_Map * const          SHIM_RESTRICT input_map_ptr,
			   Shim_Map * const          SHIM_RESTRICT output_map_ptr,
			   char const * const        SHIM_RESTRICT output_filename);
void SHIM_PUBLIC
symm_dragonfly_v1_decrypt (Symm_Dragonfly_V1_Decrypt * const SHIM_RESTRICT dfly_dcrypt_p,
			   Shim_Map * const                  SHIM_RESTRICT input_map_p,
			   Shim_Map * const                  SHIM_RESTRICT output_map_p,
			   char const * const                SHIM_RESTRICT output_fname);
void SHIM_PUBLIC
symm_dragonfly_v1_dump_header (Shim_Map * const SHIM_RESTRICT input_map_ptr,
			       char const *     SHIM_RESTRICT filename);

SHIM_END_DECLS




#endif /* ~ SYMM_DRAGONFLY_V1_H */
