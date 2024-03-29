project('PPQ', 'c', default_options: ['c_std=c17', 'optimization=3', 'buildtype=release', 'strip=true'])
_PROJECT = 'PPQ'
_LANG = 'c'
_UNIXLIKE_OPERATING_SYSTEMS  = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux']
_SUPPORTED_OPERATING_SYSTEMS = _UNIXLIKE_OPERATING_SYSTEMS + ['windows']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
_SUPPORTED_COMPILERS         = _GCC_COMPATIBLE_COMPILERS + ['msvc']

_LIB_DIRS = {
  'bsd': ['/usr/lib', '/usr/local/lib'],
  'linux': ['/usr/lib64', '/usr/lib'],
  'windows': 'C:\lib'
}

compiler = meson.get_compiler(_LANG)
os = host_machine.system()
static = get_option('static') # Are we building a static lib?
SSC_static = get_option('SSC_static') # Are we using SSC as a static lib?
lua = get_option('lua') # Are we building Lua bindings?

assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build PPQ using an unsupported operating system!')
assert (compiler.get_id() in _SUPPORTED_COMPILERS, 'You are trying to build PPQ using an unsupported compiler!')

if os == 'windows' and compiler.get_id() == 'msvc'
  _D = '/D'
else
  _D = '-D'
endif

src = [
  'Impl/Catena512.c',
  'Impl/CSPRNG.c',
  'Impl/GraphHash.c',
  'Impl/Skein512.c',
  'Impl/Threefish512.c',
  'Impl/Ubi512.c',
  'Impl/DragonflyV1.c',
  'Impl/Random.c'
  ]
# Setup these empty arrays that we will be appending to depending on OS, etc.
lib_deps   = []
lang_flags = []
inc_dir    = []
if SSC_static
  lang_flags += _D + 'SSC_EXTERN_STATIC_LIB'
  assert(not lua, 'Cannot have Lua bindings while building a static library.')
endif
if static
  lang_flags += _D + 'PPQ_EXTERN_STATIC_LIB'
else
  lang_flags += _D + 'PPQ_EXTERN_BUILD_DYNAMIC_LIB'
endif
# Determine flags to pass to gcc-compatible compilers.
gcc_compatible_flags = [
  '-fvisibility=hidden',
  '-fstrict-aliasing',
  '-Wall',
  '-funroll-loops'
  ]
if os != 'netbsd'
  gcc_compatible_flags += '-flto'
endif

if os == 'darwin' # On MacOS we require __STDC_WANT_LIB_EXTERN1__ to be defined as 1, for access to memset_s.
  lang_flags += _D + '__STDC_WANT_LIB_EXT1__=1'
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS
  if get_option('native_optimize')
    lang_flags += '-march=native'
  endif
  if compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
    lang_flags += gcc_compatible_flags
  endif
endif

if os in ['openbsd', 'freebsd', 'netbsd', 'darwin']
  lib_dir = _LIB_DIRS.get('bsd')
elif os in ['linux', 'windows']
  lib_dir = _LIB_DIRS.get(os)
else
  assert(false, 'Unsupported OS.')
endif

if lua
  lang_flags += _D + 'SSC_EXTERN_LUA'
  src += [
	'Impl/Lua/Lua.c',
	'Impl/Lua/Threefish512.c',
	'Impl/Lua/Csprng.c',
	'Impl/Lua/Skein512.c'
  ]
  lua_dep = compiler.find_library('lua5.4', required: false, static: false, dirs: lib_dir)
  if lua_dep.found()
    lib_deps += lua_dep
    lang_flags += _D + 'SSC_EXTERN_LUA_5_4'
  else
    lib_deps += compiler.find_library('lua5.3', static: false, dirs: lib_dir)
    lang_flags += _D + 'SSC_EXTERN_LUA_5_3'
  endif
endif

if os in ['openbsd', 'freebsd', 'darwin'] # On OpenBSD, FreeBSD, MacOS, the library dependencies and 'include_install' directory are the same.
  include_install = '/usr/local/include'
  inc_dir += '/usr/local/include'
elif os == 'netbsd'
  include_install = '/usr/local/include'
  inc_dir += '/usr/pkg/include'
elif os == 'linux'
  include_install = '/usr/include'
elif os == 'windows'
  lib_deps += compiler.find_library('bcrypt')
  include_install = 'C:/include'
endif

if get_option('endian') != 'auto'
  if get_option('endian') == 'little'
    lang_flags += _D + 'SSC_EXTERN_ENDIAN=SSC_ENDIAN_LITTLE'
  endif
  if get_option('endian') == 'big'
    lang_flags += _D + 'SSC_EXTERN_ENDIAN=SSC_ENDIAN_BIG'
  endif
endif

lib_deps += compiler.find_library('SSC', static: SSC_static, dirs: lib_dir)

inc_dir += '..'

install_subdir('../PPQ', install_dir: include_install, exclude_directories: ['builddir', '.git', 'impl'], exclude_files: '.gitignore')

if os == 'windows'
  if static
    static_library('PPQ', sources: src, dependencies: lib_deps, c_args: lang_flags, include_directories: inc_dir,
      name_suffix: 'lib', name_prefix: '', install: true, install_dir: 'C:\lib')
  else
    shared_library('PPQ', sources: src, dependencies: lib_deps, c_args: lang_flags, include_directories: inc_dir,
      name_suffix: 'dll', name_prefix: '', install: true, install_dir: 'C:\lib')
  endif
else
  assert (os in _UNIXLIKE_OPERATING_SYSTEMS, 'This branch covers unixlike operating systems.')
  if static
    static_library('PPQ', sources: src, dependencies: lib_deps, c_args: lang_flags, include_directories: inc_dir, install: true)
  else
    shared_library('PPQ', sources: src, dependencies: lib_deps, c_args: lang_flags, include_directories: inc_dir, install: true)
  endif
endif
