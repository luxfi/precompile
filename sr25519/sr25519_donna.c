// sr25519_donna.c — Unity build for sr25519-donna C library.
// CGO compiles this file automatically when CGO_ENABLED=1.
//
// NOTE: ed25519.c is NOT included because ristretto255.h already pulls in
// all ed25519-donna curve arithmetic via ed25519-donna.h. Including ed25519.c
// would cause symbol redefinitions in the unity build.

#include "donna/src/memzero.c"
#include "donna/src/sha2.c"
#include "donna/src/randombytes_sysrandom.c"
#include "donna/src/sr25519-randombytes-default.c"
#include "donna/src/core.c"
#include "donna/src/ristretto255.c"
#include "donna/src/merlin.c"
#include "donna/src/vrf.c"
#include "donna/src/sr25519.c"
