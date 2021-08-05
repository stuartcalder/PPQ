#include <Skc/macros.h>
#include <Skc/rand.h>
#include <Skc/lua/lua.h>
#include <Skc/lua/threefish512_ctr.h>	/* Submodule 1 */
#include <Skc/lua/csprng.h>		/* Submodule 2 */
#include <Skc/lua/skein512.h>		/* Submodule 3 */
#define NUM_SUBMODULES_ 3
#define NUM_FREE_PROCS_ 3
#define NUM_RECORDS_	(NUM_SUBMODULES_ + NUM_FREE_PROCS_)
#define LOAD_SUBMODULE_(L, submodule) BASE_LUA_LOAD_SUBMODULE(L, Skc, submodule)

/* Free Proc 1 */
static int skc_lua_random (lua_State* L) {
	Skc_Lua_CSPRNG* csprng;
	{
		const int type = lua_getfield(L, LUA_REGISTRYINDEX, SKC_LUA_CSPRNG_RKEY);
		if (type == LUA_TUSERDATA)
			csprng = SKC_LUA_CSPRNG_CHECK(L, -1);
		else
			return luaL_error(L, "Failed to load CSPRNG!");
		lua_pop(L, 1);
	}
	const int num_args = lua_gettop(L);
	switch (num_args) { /* Get the minimum and maximum. */
		case 2:  {
			lua_Integer int_1, int_2, distance;
		/* Return a pseudorandom integer in the range [int_1,int_2]. */
			int_1 = luaL_checkinteger(L, 1);
			int_2 = luaL_checkinteger(L, 2);
			if (int_2 < int_1)
				luaL_error(L, "Argument 2 was less than argument 1!");
			distance = int_2 - int_1;
			lua_pushinteger(L, int_1 + (lua_Integer)Skc_rand_nat_num(csprng, (uint64_t)distance));
			return 1;
		} case 1: {
		/* Return random(1, var_max) unless var_max is 0. In that case, return a totally random integer. */
			const lua_Integer i = luaL_checkinteger(L, 1);
			if (i == 0) {
				uint64_t u;
				Skc_rand_uint64(csprng, &u);
				lua_pushinteger(L, (lua_Integer)u);
				return 1;
			}
			if (i < 1)
				return luaL_error(L, "Argument was less than 1!");
			lua_pushinteger(L, (lua_Integer)1 + (lua_Integer)Skc_rand_nat_num(csprng, (uint64_t)(i - 1)));
			return 1;
		} case 0: {
		/* Return a random bool.
		 * 	This is where Skc's random differs from Lua's default random function. */
			uint8_t rnd;
			Skc_CSPRNG_get(csprng, &rnd, sizeof(rnd));
			lua_pushboolean(L, (rnd & UINT8_C(0x01)) != UINT8_C(0));
			return 1;
		} default:
			return luaL_error(L, "Unsupported number of arguments: %d", num_args);
	}
	return 1;
}
static int skc_lua_reseed (lua_State* L) {
	Skc_Lua_CSPRNG* csprng;
	{
		const int type = lua_getfield(L, LUA_REGISTRYINDEX, SKC_LUA_CSPRNG_RKEY);
		if (type == LUA_TUSERDATA)
			csprng = SKC_LUA_CSPRNG_CHECK(L, -1);
		else 
			return luaL_error(L, "Failed to load CSPRNG!");
		lua_pop(L, 1);
	}
	const uint8_t* seed;
	if (!(seed = (const uint8_t*)lua_touserdata(L, 1)))
		return luaL_error(L, "Invalid pointer!");
	Skc_CSPRNG_reseed(csprng, seed);
	return 0;
}
static int skc_lua_os_reseed (lua_State* L) {
	Skc_Lua_CSPRNG* csprng;
	{
		const int type = lua_getfield(L, LUA_REGISTRYINDEX, SKC_LUA_CSPRNG_RKEY);
		if (type == LUA_TUSERDATA)
			csprng = SKC_LUA_CSPRNG_CHECK(L, -1);
		else
			return luaL_error(L, "Failed to load CSPRNG!");
		lua_pop(L, 1);
	}
	Skc_CSPRNG_os_reseed(csprng);
	return 0;
}

static const luaL_Reg free_procs[] = {
	{"random", skc_lua_random},	  /* Free Proc 1 */
	{"reseed", skc_lua_reseed},	  /* Free Proc 2 */
	{"os_reseed", skc_lua_os_reseed}, /* Free Proc 3 */
	{NULL    , NULL}
};

#ifdef CSPRNG
#  undef CSPRNG
#endif
#ifdef Threefish512_CTR
#  undef Threefish512_CTR
#endif

int luaopen_Skc (lua_State* L) {
	lua_createtable(L, 0, NUM_RECORDS_);
	luaL_setfuncs(L, free_procs, 0);
	LOAD_SUBMODULE_(L, CSPRNG);
	LOAD_SUBMODULE_(L, Threefish512_CTR);
	LOAD_SUBMODULE_(L, Skein512);
	return 1;
}
