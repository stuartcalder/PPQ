#if !defined(SKC_LUA_H) && defined(BASE_EXTERN_LUA)
#define SKC_LUA_H

#include <Skc/lua/macros.h>

BASE_BEGIN_C_DECLS
SKC_API int luaopen_Skc (lua_State* L);
BASE_END_C_DECLS

#endif
