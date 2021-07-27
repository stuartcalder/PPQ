#if !defined(SKC_LUA_H) && defined(SKC_EXTERN_LUA)
#define SKC_LUA_H

#include <Skc/lua/macros.h>

BASE_BEGIN_DECLS
SKC_API int luaopen_Skc (lua_State* L);
BASE_END_DECLS

#endif
