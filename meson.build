# Symm
project('symm', 'c',
  default_options:['c_std=c18', 'buildtype=release',
		   'optimization=3', 'strip=true'])
# Determine compiler, operating system.
cc = meson.get_compiler('c')
os = host_machine.system()
_SUPPORTED_OPERATING_SYSTEMS = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux', 'windows']
_SUPPORTED_COMPILERS         = ['gcc', 'clang', 'msvc']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
# Assert that we are building on a supported operating system, with a supported compiler.
assert (os in _SUPPORTED_OPERATING_SYSTEMS,  'You are trying to build SSC using an unsupported operating system!')
assert (cc.get_id() in _SUPPORTED_COMPILERS, 'You are tryingt o build SSC using an unsupported compiler!')
# Determine what prefix to use when passing macro defines.
if os == 'windows' and cc.get_id() == 'msvc'
	_D_PREFIX = '/D'
else
	_D_PREFIX = '-D'
endif
symm_src = [
  'catena.c', 'csprng.c', 'graph_hashing.c', 'skein512.c', 'threefish512.c', 'ubi512.c'
  ]
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
if os != 'netbsd'
	gcc_compatible_flags += '-flto' # Link-time optimizations (Disabled by default on NetBSD)
endif

# On OSX we require __STDC_WANT_LIB_EXT1__ to be defined as 1, for access to memset_s.
if os == 'darwin'
	_flag = _D_PREFIX + '__STDC_WANT_LIB_EXT1__=1'
	c_flags += _flag
endif
# On OpenBSD, FreeBSD, and OSX, the library dependencies and 'include_install' directory are the same.
if os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		c_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	include_install = '/usr/local/include'
# NetBSD uses different directories than the others, with pkgsrc.
elif os == 'netbsd'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		c_flags += gcc_compatible_flags
	endif
	lib_deps += cc.find_library('ncurses', dirs: '/usr/pkg/lib')
	include_install = '/usr/local/include'
	inc_dir += '/usr/pkg/include'
# On GNU/Linux, we need ncurses as on the BSD's, but we also need tinfo. Use /usr/include for the 'include_install' directory.
elif os == 'linux'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		c_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	lib_deps  += cc.find_library('tinfo')
	include_install = '/usr/include'
# On Win64, define SSC_BUILD_STATIC and use bcrypt.dll for access to the newer Microsoft crypto API. Use C:/include as the 'include_install' directory.
elif os == 'windows'
	lib_deps += cc.find_library('bcrypt')
	include_install = 'C:/include'
endif

inc_dir += '..'

# Install the ssc git project directory into the specified include directory, where code that depends upon ssc will find ssc.
install_subdir('../symm', install_dir: include_install, exclude_directories: ['builddir', '.git'], exclude_files: '.gitignore')

# For Win64, build ssc as a static library: ssc.lib
##if os == 'windows'
##static_library('symm', sources: ssc_src, dependencies: lib_deps,
###		       c_args: c_flags, include_directories: inc_dir#,
##		       name_suffix: 'lib', name_prefix: '',
##		       install: true, install_dir: 'C:/lib')
## For Unix-like systems, build ssc as a shared object library: libssc.so
if os == 'windows'
  shared_library('symm', sources: symm_src, dependencies: lib_deps,
		 c_args: c_flags, include_directories: inc_dir,
		 name_suffix: 'dll', name_prefix: '',
		 install: true, install_dir: 'C:/lib')
else
  shared_library('symm', sources: symm_src, dependencies: lib_deps,
		 c_args: c_flags, include_directories: inc_dir,
		 install: true)
endif
