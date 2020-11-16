#ifndef SYMM_COMMON_H
#define SYMM_COMMON_H

/* Shim headers */
#include <shim/macros.h>
#include <shim/operations.h>
#include <shim/map.h>
#include <shim/mlock.h>
/* Symm headers */
#include "macros.h"
#include "threefish512.h"
#include "ubi512.h"
#include "skein512.h"
#include "csprng.h"
#include <limits.h>
#include <string.h>
#include <stdbool.h>

#if    defined (SHIM_OS_UNIXLIKE)
#	define SYMM_COMMON_NEWLINE	"\n"
#elif  defined (SHIM_OS_WINDOWS)
#	define SYMM_COMMON_NEWLINE	"\n\r"
#else
#	error "Unsupported OS."
#endif

#define SYMM_COMMON_PROMPT	SYMM_COMMON_NEWLINE "> "

#define SYMM_COMMON_MAC_BYTES			SYMM_THREEFISH512_BLOCK_BYTES
#define SYMM_COMMON_MAX_PASSWORD_BYTES		 120
#define SYMM_COMMON_MAX_PASSWORD_BYTES_STR	"120"
#define SYMM_COMMON_PASSWORD_BUFFER_BYTES	(SYMM_COMMON_MAX_PASSWORD_BYTES + 1)
#define SYMM_COMMON_PASSWORD_PROMPT		"Please input a password (max length " SYMM_COMMON_MAX_PASSWORD_BYTES_STR " characters)." SYMM_COMMON_PROMPT
#define SYMM_COMMON_REENTRY_PROMPT		"Please input the same password again." SYMM_COMMON_PROMPT
#define SYMM_COMMON_ENTROPY_PROMPT		"Please input up to " SYMM_COMMON_MAX_PASSWORD_BYTES_STR " characters." SYMM_COMMON_PROMPT

enum {
	SYMM_COMMON_PAD_MODE_ADD,
	SYMM_COMMON_PAD_MODE_TARGET
};

typedef struct {
	Symm_CSPRNG csprng;
	uint8_t     password_buffer [SYMM_COMMON_PASSWORD_BUFFER_BYTES];
	uint8_t	    check_buffer    [SYMM_COMMON_PASSWORD_BUFFER_BYTES];
	uint64_t    password_size;
	uint64_t    padding_bytes;
	int         padding_mode;
	bool        supplement_entropy;
	uint8_t     g_low;
	uint8_t     g_high;
	uint8_t     lambda;
	uint8_t     use_phi;
} Symm_Catena_Input;
#undef CHECK_BUFFER_BYTES_


#endif /* ~ SYMM_COMMON_H */
