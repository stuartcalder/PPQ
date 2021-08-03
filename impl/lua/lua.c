#include <Skc/macros.h>
#include <Skc/lua/lua.h>
#include <Skc/lua/threefish512_ctr.h>	/* Submodule 1 */
#define NUM_SUBMODULES_ 1
#define NUM_FREE_PROCS_ 1
#define NUM_RECORDS_	(NUM_SUBMODULES_ + NUM_FREE_PROCS_)
#define LOAD_SUBMODULE_(L, submodule) BASE_LUA_LOAD_SUBMODULE(L, Skc, submodule)

/* Free Proc 1 */
static int skc_lua_random (lua_State* L) {
	const int num_args = lua_gettop(L);
	lua_Integer var_min, var_max;
	switch (num_args) { /* Get the minimum and maximum. */
		case 2:
			var_min = luaL_checkinteger(L, 1);
			var_max = luaL_checkinteger(L, 2);
			break;
		case 1:
			var_min = 1;
			var_max = luaL_checkinteger(L, 1);
			break;
		case 0:
			var_min = 0;
			var_max = 1;
			break;
		default:
			return luaL_error(L, "Needed 2 arguments but got %d", num_args);
	}
	return 1;
}

static const luaL_Reg free_procs[] = {
	{"random", skc_lua_random}, /* Free Proc 1 */
	{NULL    , NULL}
};

int luaopen_Skc (lua_State* L) {
	lua_createtable(L, 0, NUM_RECORDS_);
	luaL_setfuncs(L, free_procs, 0);
	LOAD_SUBMODULE_(L, Threefish512_CTR);
	return 1;
}

