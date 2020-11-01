#ifndef SYMM_MACROS_H
#define SYMM_MACROS_H
#include <shim/macros.h>

#ifdef SYMM_EXT_BUILD
#	define SYMM_API SHIM_EXPORT_SYMBOL
#else
#	define SYMM_API SHIM_IMPORT_SYMBOL
#endif

#endif /* ~ SYMM_MACROS_H */
