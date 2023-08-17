# PPQ
Cryptography Library
## Purpose
A simple C library implementing the SHA3 competition finalist Skein, its block cipher Threefish, and the Password Hashing Competition finalist, CATENA.
Slight modifications to CATENA include: simplifying some of the ad-hoc hashing operations to produce greater-than-N-bytes of a cryptographic hash function
using Skein, as Skein can output an arbitrary amount of bytes natively.
## Dependencies
-	[meson](https://mesonbuild.com) Build System
-	[SSC](https://github.com/stuartcalder/SSC) OS Abstraction and Utilities Library
### Building SSC
#### On Linux
1. Build and install [SSC](https://github.com/stuartcalder/SSC).
2. Execute the following:
```
	$ meson --prefix /usr builddir
	$ cd builddir
	$ ninja
	# ninja install
```
#### On MacOS, BSDs
1. Build and install [SSC](https://github.com/stuartcalder/SSC).
2. Execute the following:
```
	$ meson builddir
	$ cd builddir
	$ ninja
	# ninja install
```
#### On Windows
1. git clone [SSC](https://github.com/stuartcalder/SSC) and cd into it.
2. Open an __"x64 Native Tools Command Prompt for VS 2022"__ cmd prompt, then cd into the cloned SSC project directory.
3. Execute the following:
```
	mkdir builddir
	meson --backend=ninja builddir
	cd builddir
	ninja
	ninja install
```
