#ifndef SYMM_MACROS_H
#define SYMM_MACROS_H
#include <shim/errors.h>
#include <shim/macros.h>

#ifdef SYMM_EXT_DEBUG
#	define SYMM_ASSERT_MSG(boolean, msg_ptr) shim_assert_msg(boolean, msg_ptr)
#	define SYMM_ASSERT(boolean)		 shim_assert(boolean)
#else
#	define SYMM_ASSERT_MSG(boolean, msg_ptr) /* Nil */
#	define SYMM_ASSERT(boolean)		 /* Nil */
#endif

#ifdef SYMM_EXT_STATIC_LIB
#	define SYMM_API
#else
#	ifdef SYMM_EXT_BUILD_DYNAMIC_LIB
#		define SYMM_API SHIM_EXPORT_SYMBOL
#	else /* Assume Symm is being imported as a dynamic lib. */
#		define SYMM_API SHIM_IMPORT_SYMBOL
#	endif
#endif

#endif /* ~ SYMM_MACROS_H */
