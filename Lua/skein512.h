#if !defined(SKC_LUA_SKEIN512_H) && defined(BASE_EXTERN_LUA)
#define SKC_LUA_SKEIN512_H

#include <Skc/lua/macros.h>
#include <Skc/skein512.h>

#define SKC_LUA_SKEIN512_MT		"Skc_Skein512"
#define SKC_LUA_SKEIN512_NEW(L)		BASE_LUA_NEW_UD(L, Skc_Lua_Skein512)
#define SKC_LUA_SKEIN512_CHECK(L, idx)	BASE_LUA_CHECK_UD(L, idx, Skc_Lua_Skein512, SKC_LUA_SKEIN512_MT)
#define SKC_LUA_SKEIN512_TEST(L, idx)	BASE_LUA_TEST_UD(L, idx, Skc_Lua_Skein512, SKC_LUA_SKEIN512_MT)

typedef Skc_UBI512 Skc_Lua_Skein512;
#define SKC_LUA_SKEIN512_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Lua_Skein512, 0)

BASE_BEGIN_C_DECLS
SKC_API int luaopen_Skc_Skein512 (lua_State*);
BASE_END_C_DECLS

#endif /* ! */
