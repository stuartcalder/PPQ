#if !defined(SKC_LUA_THREEFISH512_CTR_H) && defined(BASE_EXTERN_LUA)
#define SKC_LUA_THREEFISH512_CTR_H

#include <Skc/lua/macros.h>
#include <Skc/threefish512.h>

#define SKC_LUA_THREEFISH512_CTR_MT		"Skc_Threefish512_CTR"
#define SKC_LUA_THREEFISH512_CTR_NEW(L)		BASE_LUA_NEW_UD(L, Skc_Lua_Threefish512_CTR)
#define SKC_LUA_THREEFISH512_CTR_CHECK(L, idx)	BASE_LUA_CHECK_UD(L, idx, Skc_Lua_Threefish512_CTR, SKC_LUA_THREEFISH512_CTR_MT)
#define SKC_LUA_THREEFISH512_CTR_TEST(L, idx)	BASE_LUA_TEST_UD(L, idx, Skc_Lua_Threefish512_CTR, SKC_LUA_THREEFISH512_CTR_MT)

typedef struct {
	Skc_Threefish512_CTR	ctr;
	uint64_t		idx;
} Skc_Lua_Threefish512_CTR;
#define SKC_LUA_THREEFISH512_CTR_NULL_LITERAL \
 BASE_COMPOUND_LITERAL(Skc_Lua_Threefish512_CTR, \
                       SKC_THREEFISH512_CTR_NULL_LITERAL, \
		       UINT64_C(0))

BASE_BEGIN_C_DECLS
SKC_API int luaopen_Skc_Threefish512_CTR (lua_State* L);
BASE_END_C_DECLS

#endif
