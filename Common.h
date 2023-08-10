/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_COMMON_H
#define PPQ_COMMON_H

/* Std headers. */
#include <limits.h>
#include <string.h>
#include <stdbool.h>
/* SSC headers. */
#include <SSC/Macro.h>
#include <SSC/Operation.h>
#include <SSC/MemMap.h>
#include <SSC/MemLock.h>
/* PPQ headers. */
#include "Macro.h"
#include "CSPRNG.h"
#include "Skein512.h"
#include "Threefish512.h"
#include "Ubi512.h"

#if   defined(SSC_OS_UNIXLIKE)
 #define PPQ_COMMON_NEWLINE "\n"
#elif defined(SSC_OS_WINDOWS)
 #define PPQ_COMMON_NEWLINE "\n\r"
#else
 #error "Unsupported OS."
#endif

#define PPQ_COMMON_PROMPT			PPQ_COMMON_NEWLINE "> "

#define PPQ_COMMON_MAC_BYTES			PPQ_THREEFISH512_BLOCK_BYTES
#define PPQ_COMMON_MAX_PASSWORD_BYTES		120
#define PPQ_COMMON_PASSWORD_BUFFER_BYTES	(PPQ_COMMON_MAX_PASSWORD_BYTES + 1)
#define PPQ_COMMON_PASSWORD_PROMPT		"Please input a password (max length " SSC_STRINGIFY(PPQ_COMMON_MAX_PASSWORD_BYTES) " characters)." PPQ_COMMON_PROMPT
#define PPQ_COMMON_REENTRY_PROMPT		"Please input the same password again." PPQ_COMMON_PROMPT
#define PPQ_COMMON_ENTROPY_PROMPT		"Please input up to " SSC_STRINGIFY(PPQ_COMMON_MAX_PASSWORD_BYTES) " random characters)." PPQ_COMMON_PROMPT

#define PPQ_PAD_MODE_NONE   0
#define PPQ_PAD_MODE_ADD    1 /* Add x many bytes to the ciphertext. */
#define PPQ_PAD_MODE_TARGET 2 /* Add as many bytes as necessary to produce a ciphertext of x bytes. */
#define PPQ_PAD_MODE_ASIF   3 /* Add as many bytes as necessary to emulate an unpadded plaintext of x bytes. */
typedef int_fast8_t PPQ_Pad_Mode_t;

#define PPQ_COMMON_PAD_MODE_ADD    PPQ_PAD_MODE_ADD
#define PPQ_COMMON_PAD_MODE_TARGET PPQ_PAD_MODE_TARGET
#define PPQ_COMMON_PAD_MODE_ASIF   PPQ_PAD_MODE_ASIF

SSC_BEGIN_C_DECLS

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
	PPQ_CSPRNG     csprng;
	uint8_t        password_buffer [PPQ_COMMON_PASSWORD_BUFFER_BYTES];
	uint8_t	       check_buffer    [PPQ_COMMON_PASSWORD_BUFFER_BYTES];
	int64_t        password_size;
	int64_t        padding_bytes;
	bool           supplement_entropy;
	PPQ_Pad_Mode_t padding_mode;
	uint8_t        g_low;
	uint8_t        g_high;
	uint8_t        lambda;
	uint8_t        use_phi;
} PPQ_Catena512Input;
#define PPQ_CATENA512INPUT_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Catena512_Input, 0)
/*====================================================================================*/

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
typedef struct {
  PPQ_CSPRNG     rng;
  int64_t        pad_bytes;
  PPQ_Pad_Mode_t pad_mode;
  bool           supplement_entropy;
} PPQ_KeyfileInput;
#define PPQ_KEYFILEINPUT_NULL_LITERAL SSC_COMPOUND_LITERAL(PPQ_Keyfile_Input, 0)
/*====================================================================================*/

SSC_END_C_DECLS

#endif /* ~ PPQ_COMMON_H */
