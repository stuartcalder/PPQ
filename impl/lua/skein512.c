#include <Skc/lua/skein512.h>

#define MT_		SKC_LUA_SKEIN512_MT
#define RKEY_		SKC_LUA_SKEIN512_RKEY
#define NEW_(L)		SKC_LUA_SKEIN512_NEW(L)
#define CHECK_(L, idx)	SKC_LUA_SKEIN512_CHECK(L, idx)
#define TEST_(L, idx)	SKC_LUA_SKEIN512_TEST(L, idx)
#define NULL_		SKC_LUA_SKEIN512_NULL_LITERAL

typedef Skc_Lua_Skein512 Skein512_t;

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

int luaopen_Skc_Skein512 (lua_State* L) {
	//TODO
	return 1;
}
