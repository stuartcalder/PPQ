/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#ifndef PPQ_MACRO_H
#define PPQ_MACRO_H

#include <SSC/Macro.h>
#include <SSC/Error.h>
#include <SSC/Typedef.h>

#ifdef PPQ_EXTERN_DEBUG
 #define PPQ_ASSERT(Boolean) SSC_assert(Boolean)
 #define PPQ_ASSERT_MSG(...) SSC_assertMsg(__VA_ARGS__)
#else
 #define PPQ_ASSERT(Boolean) /* Nil */
 #define PPQ_ASSERT_MSG(...) /* Nil */
#endif

#ifdef PPQ_EXTERN_STATIC_LIB
 #define PPQ_API /* Nil */
 #define PPQ_API_IS_NIL
#else
 #ifdef PPQ_EXTERN_BUILD_DYNAMIC_LIB
  #define PPQ_API SSC_EXPORT
  #define PPQ_API_IS_EXPORT
  #ifdef SSC_EXPORT_IS_NIL
   #define PPQ_API_IS_NIL
  #endif
 #else /* Assume PPQ is being imported as a dynamic lib. */
  #define PPQ_API SSC_IMPORT
  #define PPQ_API_IS_IMPORT
  #ifdef SSC_IMPORT_IS_NIL
   #define PPQ_API_IS_NIL
  #endif
 #endif
#endif
#define PPQ_INLINE SSC_INLINE

#define PPQ_BEGIN_C_DECLS SSC_BEGIN_C_DECLS
#define PPQ_END_C_DECLS   SSC_END_C_DECLS
#if defined(SSC_BEGIN_C_DECLS_IS_NIL) && defined(SSC_END_C_DECLS_IS_NIL)
 #define PPQ_BEGIN_C_DECLS_IS_NIL
 #define PPQ_END_C_DECLS_IS_NIL
#endif

#define PPQ_RESTRICT SSC_RESTRICT
#if defined(SSC_RESTRICT_IS_NIL)
 #define PPQ_RESTRICT_IS_NIL
#endif

#endif /* ~ PPQ_MACRO_H */
