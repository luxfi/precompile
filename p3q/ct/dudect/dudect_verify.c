/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_verify.c — dudect main loop driving the P3Q precompile gate
 * through the cgo bridge in verify_ct.go.
 *
 * dudect API contract: the user provides do_one_computation(data) and
 * prepare_inputs(cfg, input, classes); dudect's `dudect_main` invokes
 * them via the extern declarations at the bottom of dudect.h. See
 * https://github.com/oreparaz/dudect/blob/master/src/dudect.h
 *
 * We define DUDECT_IMPLEMENTATION exactly once before including the
 * header so the whole library compiles into this translation unit.
 *
 * dudect_compat.h is `-include`-d by the Makefile on AArch64 hosts;
 * on x86 it is a no-op.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported by libp3q_verify (verify_ct.go). */
extern int    p3q_verify_ct_setup(void);
extern size_t p3q_verify_ct_input_size(void);
extern size_t p3q_verify_ct_pool_size(void);
extern int    p3q_verify_ct_copy_pool(size_t idx, uint8_t *dst);
extern void   p3q_verify_ct(uint8_t *data);

/* Per-sample input width. Filled in main() after setup. */
static size_t g_chunk_size = 0;
static size_t g_pool_size  = 0;

/*
 * dudect API hook: populate cfg->number_measurements samples of
 * cfg->chunk_size bytes each, and assign each sample a binary class
 * label (0 = fixed class A, 1 = varying-but-valid class B). dudect
 * supplies randombytes() / randombit() for us — same RNG it uses
 * internally, so the class assignment is uncorrelated with anything
 * Run() could see.
 *
 * Both classes are STRUCTURALLY VALID inputs (magic header in place,
 * lengths consistent). They differ only in proof / pub byte payload.
 * This is the operationally meaningful CT population — see verify_ct.go
 * header for the full framing.
 *
 * Class A is always pool[0] (byte-identical across class-A samples as
 * Welch's t-test requires); class B is pool[rand % pool_size] (varying
 * valid inputs drawn uniformly from the precomputed pool).
 */
void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            /* Class A: pool[0] every time. */
            (void)p3q_verify_ct_copy_pool(0, slot);
        } else {
            /* Class B: a uniformly-drawn valid input from the pool. */
            uint8_t pick_buf[8];
            randombytes(pick_buf, sizeof pick_buf);
            uint64_t pick = 0;
            for (size_t k = 0; k < sizeof pick_buf; k++) {
                pick = (pick << 8) | pick_buf[k];
            }
            (void)p3q_verify_ct_copy_pool((size_t)(pick % g_pool_size), slot);
        }
    }
}

/* dudect API hook: invoke the SUT on one sample of cfg->chunk_size
 * bytes. cgo bridge handles the slice header. */
uint8_t do_one_computation(uint8_t *data) {
    p3q_verify_ct(data);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (p3q_verify_ct_setup() != 0) {
        fprintf(stderr, "p3q_verify_ct_setup failed\n");
        return 1;
    }
    g_chunk_size = p3q_verify_ct_input_size();
    g_pool_size  = p3q_verify_ct_pool_size();
    if (g_chunk_size == 0 || g_pool_size == 0) {
        fprintf(stderr, "p3q dudect: setup yielded zero size\n");
        return 1;
    }

    /* Per-batch sample count. The DUDECT_SAMPLES env var allows
     * scaling up to the submission-grade 10^9 run; smoke runs use
     * the default (10000). */
    size_t samples = 10000;
    if (const char *s = (const char *)getenv("DUDECT_SAMPLES")) {
        long n = strtol(s, NULL, 10);
        if (n > 0 && n < 1000000000L) samples = (size_t)n;
        else if (n >= 1000000000L)    samples = 1000000000U;
    }
    size_t batches = 4;
    if (const char *s = (const char *)getenv("DUDECT_MAX_BATCHES")) {
        long n = strtol(s, NULL, 10);
        if (n > 0 && n < 100000L)     batches = (size_t)n;
    }

    dudect_config_t cfg = {
        .chunk_size            = g_chunk_size,
        .number_measurements   = samples,
        .number_percentiles    = 100,
    };

    dudect_ctx_t ctx;
    dudect_init(&ctx, &cfg);

    fprintf(stderr,
            "p3q dudect: chunk_size=%zu samples=%zu batches=%zu "
            "pool=%zu\n",
            g_chunk_size, samples, batches, g_pool_size);

    int verdict = 0;
    for (size_t b = 0; b < batches; b++) {
        verdict = (int)dudect_main(&ctx);
        if (verdict == DUDECT_LEAKAGE_FOUND) {
            fprintf(stderr, "[FAIL] dudect detected leakage in batch %zu\n", b);
            break;
        }
    }
    dudect_free(&ctx);
    return verdict == DUDECT_LEAKAGE_FOUND ? 1 : 0;
}
