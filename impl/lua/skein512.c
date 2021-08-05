#include <Skc/lua/skein512.h>

#define MT_		SKC_LUA_SKEIN512_MT
#define NEW_(L)		SKC_LUA_SKEIN512_NEW(L)
#define CHECK_(L, idx)	SKC_LUA_SKEIN512_CHECK(L, idx)
#define TEST_(L, idx)	SKC_LUA_SKEIN512_TEST(L, idx)
#define NULL_		SKC_LUA_SKEIN512_NULL_LITERAL

typedef Skc_Lua_Skein512 Skein512_t;

static int skein512_hash (lua_State* L) {
	Skein512_t* sk;
	uint8_t *bytes_out, *bytes_in;
	uint64_t num_bytes_in, num_bytes_out;

	sk = CHECK_(L, 1);
	if (!(bytes_out = (uint8_t*)lua_touserdata(L, 2)))
		return luaL_error(L, "Invalid ptr arg %d.", 1);
	if (!(bytes_in = (uint8_t*)lua_touserdata(L, 3)))
		return luaL_error(L, "Invalid ptr arg %d.", 2);
	num_bytes_in  = (uint64_t)luaL_checkinteger(L, 4);
	num_bytes_out = (uint64_t)luaL_checkinteger(L, 5);
	Skc_Skein512_hash(sk, bytes_out, bytes_in, num_bytes_in, num_bytes_out);
	return 0;
}

static int skein512_hash_native (lua_State* L) {
	Skein512_t* sk;
	uint8_t *bytes_out, *bytes_in;
	uint64_t num_bytes_in;

	sk = CHECK_(L, 1);
	if (!(bytes_out = (uint8_t*)lua_touserdata(L, 2)))
		return luaL_error(L, "Invalid ptr arg %d.", 1);
	if (!(bytes_in = (uint8_t*)lua_touserdata(L, 3)))
		return luaL_error(L, "Invalid ptr arg %d.", 2);
	num_bytes_in = (uint64_t)luaL_checkinteger(L, 4);
	Skc_Skein512_hash_native(sk, bytes_out, bytes_in, num_bytes_in);
	return 0;
}

static int skein512_mac (lua_State* L) {
	Skein512_t* sk;
	uint8_t* bytes_out;
	const uint8_t* bytes_in;
	const uint8_t* key_in;
	uint64_t num_bytes_in;
	uint64_t num_bytes_out;

	sk = CHECK_(L, 1);
	if (!(bytes_out = (uint8_t*)lua_touserdata(L, 2)))
		return luaL_error(L, "Invalid ptr arg %d.", 1);
	if (!(bytes_in = (uint8_t*)lua_touserdata(L, 3)))
		return luaL_error(L, "Invalid ptr arg %d.", 2);
	if (!(key_in = (uint8_t*)lua_touserdata(L, 4)))
		return luaL_error(L, "Invalid ptr arg %d.", 3);
	num_bytes_in  = (uint64_t)luaL_checkinteger(L, 5);
	num_bytes_out = (uint64_t)luaL_checkinteger(L, 6);
	Skc_Skein512_mac(sk, bytes_out, bytes_in, key_in, num_bytes_in, num_bytes_out);
	return 0;
}

static int skein512_new (lua_State* L) {
	Skein512_t* sk = NEW_(L);
	*sk = NULL_;
	luaL_getmetatable(L, MT_);
	lua_setmetatable(L, -2);
	return 1;
}

static int skein512_del (lua_State* L) {
	Skein512_t* sk = CHECK_(L, 1);
	*sk = NULL_;
	return 0;
}

static const luaL_Reg skein512_methods[] = {
	{"hash"       , skein512_hash},
	{"hash_native", skein512_hash_native},
	{"mac"        , skein512_mac},
	{"__gc"       , skein512_del},
#ifdef BASE_LUA >= BASE_LUA_5_4
	{"__close"    , skein512_del},
#endif
	{NULL, NULL}
};
static const luaL_Reg free_procs[] = {
	{"new", skein512_new},
	{NULL, NULL}
};

int luaopen_Skc_Skein512 (lua_State* L) {
	if (luaL_newmetatable(L, MT_)) {
		luaL_setfuncs(L, skein512_methods, 0);
		BASE_LUA_MT_SELF_INDEX(L);
	}
	luaL_newlib(L, free_procs);
	return 1;
}
