// sr25519_donna.c — Unity build for sr25519-donna C library.
// CGO compiles this file automatically when CGO_ENABLED=1.
// C source files vendored from https://github.com/TerenceGe/sr25519-donna
//
// NOTE: ed25519.c is NOT included because ristretto255.h already pulls in
// all ed25519-donna curve arithmetic via ed25519-donna.h. Including ed25519.c
// would cause symbol redefinitions in the unity build.

#include "donna/memzero.c"
#include "donna/sha2.c"
#include "donna/randombytes_sysrandom.c"
#include "donna/sr25519-randombytes-default.c"
#include "donna/core.c"
#include "donna/ristretto255.c"
#include "donna/merlin.c"
#include "donna/vrf.c"
#include "donna/sr25519.c"
