#ifndef SYMM_CATENA_H
#define SYMM_CATENA_H

#include <shim/macros.h>
#include <shim/operations.h>
#include <shim/errors.h>
#include "ubi512.h"
#include "graph_hashing.h"

#define SYMM_CATENA_SUCCESS		0
#define SYMM_CATENA_ALLOC_FAILURE	1
#define SYMM_CATENA_SALT_BITS		256
#define SYMM_CATENA_SALT_BYTES		(SYMM_CATENA_SALT_BITS / CHAR_BIT)
#define SYMM_CATENA_MAX_PASSWORD_BYTES	120
#define SYMM_CATENA_TWEAK_BYTES		(SYMM_THREEFISH512_BLOCK_BYTES + 1 + 1 + 2 + 2)
#if    (SYMM_THREEFISH512_BLOCK_BYTES > SYMM_CATENA_SALT_BYTES)
#	define SYMM_CATENA_RNG_BYTES	SYMM_THREEFISH512_BLOCK_BYTES
#else
#	define SYMM_CATENA_RNG_BYTES	SYMM_CATENA_SALT_BYTES
#endif
#define SYMM_CATENA_DOMAIN_PWSCRAMBLER	UINT8_C (0x00)
#define SYMM_CATENA_DOMAIN_KDF		UINT8_C (0x01)
#define SYMM_CATENA_DOMAIN_POW		UINT8_C (0x02)
#define SYMM_CATENA_MHF_TEMP_BYTES	SYMM_GRAPH_HASHING_TEMP_BYTES

typedef struct SHIM_PUBLIC {
	Symm_UBI512               ubi512_ctx;
	uint8_t *	          graph_memory;
	alignas(uint64_t) uint8_t x_buffer [SYMM_THREEFISH512_BLOCK_BYTES];
	alignas(uint64_t) uint8_t salt     [SYMM_CATENA_SALT_BYTES];
	union {
		alignas(uint64_t) uint8_t tw_pw_salt [SYMM_CATENA_TWEAK_BYTES + SYMM_CATENA_MAX_PASSWORD_BYTES + SYMM_CATENA_SALT_BYTES];
		alignas(uint64_t) uint8_t flap       [SYMM_THREEFISH512_BLOCK_BYTES * 3];
		alignas(uint64_t) uint8_t catena     [SYMM_THREEFISH512_BLOCK_BYTES + sizeof(uint8_t)];
		alignas(uint64_t) uint8_t phi        [SYMM_THREEFISH512_BLOCK_BYTES * 2];
		alignas(uint64_t) uint8_t mhf        [SYMM_CATENA_MHF_TEMP_BYTES];
		struct {
			alignas(uint64_t) uint8_t word_buf [SYMM_THREEFISH512_BLOCK_BYTES * 2];
			alignas(uint64_t) uint8_t rng      [SYMM_CATENA_RNG_BYTES];
		} gamma;
	} temp;
} Symm_Catena;

SHIM_BEGIN_DECLS

int SHIM_PUBLIC
symm_catena_nophi (Symm_Catena * SHIM_RESTRICT ctx,
		   uint8_t *     SHIM_RESTRICT output,
		   uint8_t *     SHIM_RESTRICT password,
		   int const                   password_size,
		   uint8_t const               g_low,
		   uint8_t const               g_high,
		   uint8_t const               lambda);
int SHIM_PUBLIC
symm_catena_usephi (Symm_Catena * SHIM_RESTRICT ctx,
		    uint8_t *     SHIM_RESTRICT output,
		    uint8_t *     SHIM_RESTRICT password,
		    int const                   password_size,
		    uint8_t const               g_low,
		    uint8_t const               g_high,
		    uint8_t const               lambda);

SHIM_END_DECLS
#endif // ~ SYMM_CATENA_H
