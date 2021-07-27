#ifndef SKC_COMMON_H
#define SKC_COMMON_H

/* Std headers. */
#include <limits.h>
#include <string.h>
#include <stdbool.h>
/* Base headers. */
#include <Base/macros.h>
#include <Base/operations.h>
#include <Base/mmap.h>
#include <Base/mlock.h>
/* Skc headers. */
#include "csprng.h"
#include "macros.h"
#include "skein512.h"
#include "threefish512.h"
#include "ubi512.h"

#if    defined(BASE_OS_UNIXLIKE)
#	define SKC_COMMON_NEWLINE "\n"
#elif  defined(BASE_OS_WINDOWS)
#	define SKC_COMMON_NEWLINE "\n\r"
#else
#	error "Unsupported OS."
#endif

#define SKC_COMMON_PROMPT			SKC_COMMON_NEWLINE "> "

#define SKC_COMMON_MAC_BYTES			SKC_THREEFISH512_BLOCK_BYTES
#define SKC_COMMON_MAX_PASSWORD_BYTES		120
#define SKC_COMMON_PASSWORD_BUFFER_BYTES	(SKC_COMMON_MAX_PASSWORD_BYTES + 1)
#define SKC_COMMON_PASSWORD_PROMPT		"Please input a password (max length " BASE_STRINGIFY(SKC_COMMON_MAX_PASSWORD_BYTES) " characters)." SKC_COMMON_PROMPT
#define SKC_COMMON_REENTRY_PROMPT		"Please input the same password again." SKC_COMMON_PROMPT
#define SKC_COMMON_ENTROPY_PROMPT		"Please input up to " BASE_STRINGIFY(SKC_COMMON_MAX_PASSWORD_BYTES) " random characters)." SKC_COMMON_PROMPT

enum {
	SKC_COMMON_PAD_MODE_ADD,
	SKC_COMMON_PAD_MODE_TARGET,
	SKC_COMMON_PAD_MODE_ASIF
};

typedef struct {
	Skc_CSPRNG  csprng;
	uint8_t     password_buffer [SKC_COMMON_PASSWORD_BUFFER_BYTES];
	uint8_t	    check_buffer    [SKC_COMMON_PASSWORD_BUFFER_BYTES];
	int64_t     password_size;
	int64_t     padding_bytes;
	int         padding_mode;
	bool        supplement_entropy;
	uint8_t     g_low;
	uint8_t     g_high;
	uint8_t     lambda;
	uint8_t     use_phi;
} Skc_Catena512_Input;

#endif /* ~ SKC_COMMON_H */
