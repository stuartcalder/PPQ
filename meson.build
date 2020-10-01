project('symm',
	'c',
	default_options: ['c_std=c18', 'optimization=3', 'buildtype=release', 'strip=true'])

_PROJECT  = 'symm'
_LANG = 'c'

_UNIXLIKE_OPERATING_SYSTEMS  = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux']
_SUPPORTED_OPERATING_SYSTEMS = _UNIXLIKE_OPERATING_SYSTEMS + ['windows']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
_SUPPORTED_COMPILERS         = _GCC_COMPATIBLE_COMPILERS + ['msvc']

compiler = meson.get_compiler(_LANG)
os = host_machine.system()

assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build symm using an unsupported operating system!')
assert (compiler.get_id() in _SUPPORTED_COMPILERS, 'You are trying to build symm using an unsupported compiler!')

if os == 'windows' and compiler.get_id() == 'msvc'
	_D_PREFIX = '/D'
else
	_D_PREFIX = '-D'
endif

src = [
  'impl/catena.c',
  'impl/csprng.c',
  'impl/graph_hashing.c',
  'impl/skein512.c',
  'impl/threefish512.c',
  'impl/ubi512.c',
  'impl/dragonfly_v1.c'
  ]
# Setup these empty arrays that we will be appending to depending on OS, etc.
lib_deps   = []
lang_flags = []
inc_dir    = []
# Determine flags to pass to gcc-compatible compilers.
gcc_compatible_flags = [
  '-fvisibility=hidden',
  '-fstrict-aliasing',
  '-Wall',
  '-funroll-loops'
  ]
if os != 'netbsd' and compiler.get_id() != 'clang'
  gcc_compatible_flags += '-flto'
endif

if os == 'darwin' # On OSX we require __STDC_WANT_LIB_EXT1__ to be defined as 1, for access to memset_s.
  _flag = _D_PREFIX + '__STDC_WANT_LIB_EXT1__=1'
  lang_flags += _flag
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS
  if get_option('native_optimize')
    lang_flags += '-march=native'
  endif
  if compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
    lang_flags += gcc_compatible_flags
  endif
endif

if os == 'openbsd' or os == 'freebsd' or os == 'darwin' # On OpenBSD, FreeBSD, and OSX, the library dependencies and 'include_install' directory are the same.
  include_install = '/usr/local/include'
elif os == 'netbsd'
  include_install = '/usr/local/include'
  inc_dir += '/usr/pkg/include'
elif os == 'linux'
  include_install = '/usr/include'
elif os == 'windows'
  lib_deps += compiler.find_library('bcrypt')
  include_install = 'C:/include'
endif

if os == 'openbsd' or os == 'freebsd' or os == 'darwin'
  lib_deps += compiler.find_library('shim')
elif os == 'netbsd'
  lib_deps += compiler.find_library('shim')
elif os == 'linux'
  lib_deps += compiler.find_library('shim')
elif os == 'windows'
  lib_deps += compiler.find_library('shim')
endif

inc_dir += '..'

install_subdir('../symm', install_dir: include_install, exclude_directories: ['builddir', '.git', 'impl'], exclude_files: '.gitignore')

if os == 'windows'
  shared_library('symm', sources: src, dependencies: lib_deps,
		 c_args: lang_flags, include_directories: inc_dir,
		 name_suffix: 'dll', name_prefix: '',
		 install: true, install_dir: 'C:/lib')
else
  assert (os in _UNIXLIKE_OPERATING_SYSTEMS, 'This branch covers unixlike operating systems.')
  shared_library('symm', sources: src, dependencies: lib_deps,
		 c_args: lang_flags, include_directories: inc_dir,
		 install: true)
endif
