#if !defined(SKC_LUA_CSPRNG_H) && defined(BASE_EXTERN_LUA)
#define SKC_LUA_CSPRNG_H

#include <Skc/lua/macros.h>
#include <Skc/csprng.h>

#define SKC_LUA_CSPRNG_MT			"Skc_CSPRNG"
#define SKC_LUA_CSPRNG_RKEY			"Skc.csprng"
#define SKC_LUA_CSPRNG_NEW(L)			BASE_LUA_NEW_UD(L, Skc_Lua_CSPRNG)
#define SKC_LUA_CSPRNG_CHECK(L, idx)		BASE_LUA_CHECK_UD(L, idx, Skc_Lua_CSPRNG, SKC_LUA_CSPRNG_MT)
#define SKC_LUA_CSPRNG_TEST(L, idx)		BASE_LUA_TEST_UD(L, idx, Skc_Lua_CSPRNG, SKC_LUA_CSPRNG_MT)

typedef Skc_CSPRNG Skc_Lua_CSPRNG;
#define SKC_LUA_CSPRNG_NULL_LITERAL BASE_COMPOUND_LITERAL(Skc_Lua_CSPRNG, 0)

BASE_BEGIN_C_DECLS
SKC_API int luaopen_Skc_CSPRNG (lua_State*);
BASE_END_C_DECLS

#endif /* ! */
