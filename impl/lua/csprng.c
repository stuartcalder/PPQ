#include <Skc/lua/csprng.h>

#define MT_		SKC_LUA_CSPRNG_MT
#define RKEY_		SKC_LUA_CSPRNG_RKEY
#define NEW_(L)		SKC_LUA_CSPRNG_NEW(L)
#define CHECK_(L, idx)	SKC_LUA_CSPRNG_CHECK(L, idx)
#define TEST_(L, idx)	SKC_LUA_CSPRNG_TEST(L, idx)
#define NULL_		SKC_LUA_CSPRNG_NULL_LITERAL

typedef Skc_Lua_CSPRNG CSPRNG_t;

static int csprng_reseed (lua_State* L) {
	CSPRNG_t* const csprng = CHECK_(L, 1);
	uint8_t* seed;
	if (!(seed = (uint8_t*)lua_touserdata(L, 2)))
		return luaL_error(L, "Seed was not a valid pointer!");
	Skc_CSPRNG_reseed(csprng, seed);
	return 0;
}
static int csprng_os_reseed (lua_State* L) {
	CSPRNG_t* const csprng = CHECK_(L, 1);
	Skc_CSPRNG_os_reseed(csprng);
	return 0;
}
static int csprng_get (lua_State* L) {
	CSPRNG_t* const csprng = CHECK_(L, 1);
	uint8_t* output;
	if (!(output = (uint8_t*)lua_touserdata(L, 2)))
		return luaL_error(L, "Output was not a valid pointer!");
	const lua_Integer n = luaL_checkinteger(L, 3);
	Skc_CSPRNG_get(csprng, output, (uint64_t)n);
	return 0;
}
static int csprng_del (lua_State* L) {
	CSPRNG_t* const csprng = CHECK_(L, 1);
	memset(csprng, 0, sizeof(*csprng));
	return 0;
}
static int csprng_new (lua_State* L) {
	CSPRNG_t* const csprng = NEW_(L);
	*csprng = NULL_;
	Skc_CSPRNG_init(csprng);
	if (lua_gettop(L) >= 1) {
		uint8_t* seed;
		if (!(seed = (uint8_t*)lua_touserdata(L, 1)))
			return luaL_error(L, "Seed was not a valid pointer!");
		Skc_CSPRNG_reseed(csprng, seed);
	}
	luaL_getmetatable(L, MT_);
	lua_setmetatable(L, -2);
	return 1;
}

static const luaL_Reg csprng_methods[] = {
	{"reseed", csprng_reseed},
	{"os_reseed", csprng_os_reseed},
	{"get", csprng_get},
	{"del", csprng_del},
	{"__gc", csprng_del},
#if BASE_LUA >= BASE_LUA_5_4
	{"__close", csprng_del},
#endif
	{NULL, NULL}
};
static const luaL_Reg free_procs[] = {
	{"new", csprng_new},
	{NULL, NULL}
};

int luaopen_Skc_CSPRNG (lua_State* L) {
	if (luaL_newmetatable(L, MT_)) {
		luaL_setfuncs(L, csprng_methods, 0);
		BASE_LUA_MT_SELF_INDEX(L);
	}
	{ /* Create a registry-wide accessible CSPRNG. */
		const int type = lua_getfield(L, LUA_REGISTRYINDEX, RKEY_);
		lua_pop(L, 1);
		switch (type) {
			case LUA_TUSERDATA:
				break;
			case LUA_TNIL:
				lua_pushcfunction(L, csprng_new);
				if (lua_pcall(L, 0, 1, 0) != LUA_OK)
					return luaL_error(L, "csprng_new failed!");
				lua_setfield(L, LUA_REGISTRYINDEX, RKEY_);
				break;
			default:
				return luaL_error(L, "Invalid type for field Skc.csprng: %d", type);
		}
	}
	luaL_newlib(L, free_procs);
	return 1;
}
