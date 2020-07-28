# Symm
project('symm',
	'c',
	default_options:['c_std=c18', 'buildtype=release', 'optimization=3', 'strip=true'])
# Determine compiler, operating system.
cc = meson.get_compiler('c')
os = host_machine.system()
_UNIXLIKE_OPERATING_SYSTEMS  = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux']
_SUPPORTED_OPERATING_SYSTEMS = _UNIXLIKE_OPERATING_SYSTEMS + ['windows']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
_SUPPORTED_COMPILERS         = _GCC_COMPATIBLE_COMPILERS + ['msvc']
# Assert that we are building on a supported operating system, with a supported compiler.
assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build symm using an unsupported operating system!')
assert (cc.get_id() in _SUPPORTED_COMPILERS, 'You are tryingt to build symm using an unsupported compiler!')
# Determine what prefix to use when passing macro defines.
if os == 'windows' and cc.get_id() == 'msvc'
	_D_PREFIX = '/D'
else
	_D_PREFIX = '-D'
endif

symm_src = ['catena.c', 'csprng.c', 'graph_hashing.c', 'skein512.c', 'threefish512.c', 'ubi512.c']
# Setup these empty arrays that we will be appending to depending on OS, etc.
lib_deps  = []
c_flags   = []
inc_dir   = []
# Determine flags to pass to gcc-compatible compilers.
gcc_compatible_flags = [
  '-fvisibility=hidden',
  '-fstrict-aliasing',
  '-Wall',
  '-funroll-loops'
  ]
#if os != 'netbsd'
#  gcc_compatible_flags += '-flto' # Link-time optimizations (Disabled by default on NetBSD)
#endif

if os == 'darwin' # On OSX we require __STDC_WANT_LIB_EXT1__ to be defined as 1, for access to memset_s.
  _flag = _D_PREFIX + '__STDC_WANT_LIB_EXT1__=1'
  c_flags += _flag
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS and cc.get_id() in _GCC_COMPATIBLE_COMPILERS
  c_flags += gcc_compatible_flags
endif

if os == 'openbsd' or os == 'freebsd' or os == 'darwin' # On OpenBSD, FreeBSD, and OSX, the library dependencies and 'include_install' directory are the same.
  include_install = '/usr/local/include'
elif os == 'netbsd'
  include_install = '/usr/local/include'
  inc_dir += '/usr/pkg/include'
elif os == 'linux'
  include_install = '/usr/include'
elif os == 'windows'
  lib_deps += cc.find_library('bcrypt')
  include_install = 'C:/include'
endif

inc_dir += '..'

install_subdir('../symm', install_dir: include_install, exclude_directories: ['builddir', '.git'], exclude_files: '.gitignore')

if os == 'windows'
  shared_library('symm', sources: symm_src, dependencies: lib_deps,
		 c_args: c_flags, include_directories: inc_dir,
		 name_suffix: 'dll', name_prefix: '',
		 install: true, install_dir: 'C:/lib')
else
  assert (os in _UNIXLIKE_OPERATING_SYSTEMS, 'This branch covers unixlike operating systems.')
  shared_library('symm', sources: symm_src, dependencies: lib_deps,
		 c_args: c_flags, include_directories: inc_dir,
		 install: true)
endif
