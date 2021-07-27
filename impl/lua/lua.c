#include <Skc/macros.h>
#include <Skc/lua/lua.h>
#include <Skc/lua/threefish512_ctr.h>	/* Submodule 1 */
#define NUM_SUBMODULES_ 1
#define LOAD_SUBMODULE_(L, submodule) BASE_LUA_LOAD_SUBMODULE(L, Skc, submodule)

int luaopen_Skc (lua_State* L) {
	lua_createtable(L, 0, NUM_SUBMODULES_);
	LOAD_SUBMODULE_(L, Threefish512_CTR);
	return 1;
}

