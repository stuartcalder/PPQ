#include <Skc/macros.h>
#include <Skc/rand.h>
#include <Skc/lua/lua.h>
#include <Skc/lua/threefish512_ctr.h>	/* Submodule 1 */
#include <Skc/lua/csprng.h>		/* Submodule 2 */
#include <Skc/lua/skein512.h>		/* Submodule 3 */
#define NUM_SUBMODULES_ 3
#define NUM_FREE_PROCS_ 5
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
/* Free Proc 2 */
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
/* Free Proc 3 */
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
/* Free Proc 4 */
static int choose_from_pseq (lua_State* L) {
	const int n_args = lua_gettop(L);
	luaL_checktype(L, 1, LUA_TTABLE);
	lua_Integer max_v;
	if (n_args >= 2)
		max_v = luaL_checkinteger(L, 2);
	else
		max_v = 100;

	lua_Integer n;
	lua_pushcfunction(L, skc_lua_random);
	lua_pushinteger(L, max_v);
	if (lua_pcall(L, 1, 1, 0) != LUA_OK)
		return luaL_error(L, "random failed!");
	n = luaL_checkinteger(L, -1);

	lua_Integer a = 0;
	lua_len(L, 1);
	const lua_Integer seq_len = lua_tointeger(L, -1);
	/* <- [stack] */
	for (lua_Integer i = 1; i <= seq_len; ++i) {	/* For each table in the sequence... */
		if (lua_geti(L, 1, i) == LUA_TTABLE) { /* <-[stack+1] */
			int to_pop = 2;
			if (lua_geti(L, -1, 2) == LUA_TNUMBER) /* <-[stack+2] */
				a += lua_tointeger(L, -1);
			else
				return luaL_error(L, "t[2] was not a number!");
			if (n <= a) {
				const int t = lua_geti(L, -2, 1); /* <-[stack+3] */
				++to_pop;
				switch (t) {
					case LUA_TNIL:
					case LUA_TNONE:
						return luaL_error(L, "No value to return!");
				}
				return 1;
			}
			lua_pop(L, to_pop);
		} else /* Erroneously not a table. */
			return luaL_error(L, "Arg %d of sequence was NOT a table!", i);
	}
	return luaL_error(L, "Invalid probability sequence!");
}

/* Free Proc 5 */
static int string_reseed (lua_State* L) {
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
	size_t         size;
	if (!(seed = (uint8_t*)luaL_checklstring(L, 1, &size)))
		return luaL_error(L, "Invalid string!");
	
	struct {
		Skc_UBI512 ubi512;
		uint8_t    buffer [SKC_THREEFISH512_BLOCK_BYTES];
	} data;

	Skc_Skein512_hash_native(&data.ubi512,
				 data.buffer,
				 seed,
				 size);
	Skc_CSPRNG_reseed(csprng, data.buffer);
	Base_secure_zero(&data, sizeof(data));
	return 0;
}

static const luaL_Reg free_procs[] = {
	{"random"          , skc_lua_random},    /* Free Proc 1 */
	{"reseed"          , skc_lua_reseed},    /* Free Proc 2 */
	{"os_reseed"       , skc_lua_os_reseed}, /* Free Proc 3 */
	{"choose_from_pseq", choose_from_pseq},  /* Free Proc 4 */
	{"string_reseed"   , string_reseed},     /* Free Proc 5 */
	{NULL    , NULL}
};

#ifdef CSPRNG
#  undef CSPRNG
#endif
#ifdef Threefish512_CTR
#  undef Threefish512_CTR
#endif
#ifdef Skein512
#  undef Skein512
#endif

int luaopen_Skc (lua_State* L) {
	lua_createtable(L, 0, NUM_RECORDS_);
	LOAD_SUBMODULE_(L, Threefish512_CTR);
	LOAD_SUBMODULE_(L, CSPRNG);
	LOAD_SUBMODULE_(L, Skein512);
	luaL_setfuncs(L, free_procs, 0);
	return 1;
}
