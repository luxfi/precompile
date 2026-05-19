/*
 * dudect_compat.h — AArch64 compatibility shim for dudect.h.
 *
 * dudect.h unconditionally includes <emmintrin.h> and <x86intrin.h>;
 * on ARM64 those headers are absent. This shim provides equivalents
 * for the only two intrinsics dudect actually uses:
 *
 *   - _mm_mfence()   — memory fence
 *   - __rdtsc()      — read time-stamp counter
 *
 * Accuracy disclaimer
 * -------------------
 * The ARM equivalent of TSC is the CNTVCT_EL0 virtual counter. It has
 * sub-nanosecond resolution on modern Cortex / Apple cores; for
 * dudect's purposes (relative cycle distribution comparison via
 * Welch's t-test) this is adequate. We do not normalise the counter
 * frequency — dudect compares within a single run so absolute units
 * do not matter, only that the counter is monotonic and reasonably
 * granular.
 *
 * The shim defines the x86 intrinsics as static-inline equivalents
 * and blocks the x86 header includes via #define.
 */

#ifndef P3Q_DUDECT_COMPAT_H
#define P3Q_DUDECT_COMPAT_H

#if defined(__aarch64__) || defined(__arm64__)

/* Block the x86 includes — provide our own intrinsics below. */
#define _EMMINTRIN_H_INCLUDED 1
#define _X86INTRIN_H_INCLUDED 1
#define _MM_MALLOC_H_INCLUDED 1

#include <stdint.h>

static inline void _mm_mfence(void) {
    __asm__ __volatile__("dmb sy" ::: "memory");
}

static inline uint64_t __rdtsc(void) {
    uint64_t v;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

#endif /* __aarch64__ */

#endif /* P3Q_DUDECT_COMPAT_H */
