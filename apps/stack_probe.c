/* stack_probe.c -- per-primitive stack high-water benchmark (NIST API).
 *
 * Companion to benchmark_binary.c: same three primitives, but the metric is
 * peak stack depth rather than cycles.  See stackprobe.h for the method.
 *
 * Usage: stack_probe_lvlX [--iterations=N] [--stack-mb=M] [--out=FILE]
 *                         [--csv] [--no-resident]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <api.h>

#include "stack_probe_common.h"

/* Every buffer lives on the heap so the measured frames contain only what the
 * primitive itself needs. */
static unsigned char *pk, *sk, *sm, *m_out;
static unsigned long long smlen, mlen_out;
static unsigned char msg[32];
static int ok;

static void st_setup(void)
{
    pk = (unsigned char *)malloc(CRYPTO_PUBLICKEYBYTES);
    sk = (unsigned char *)malloc(CRYPTO_SECRETKEYBYTES);
    sm = (unsigned char *)malloc(CRYPTO_BYTES + sizeof msg);
    m_out = (unsigned char *)malloc(CRYPTO_BYTES + sizeof msg);
    if (!pk || !sk || !sm || !m_out) {
        fprintf(stderr, "[stack_probe] allocation failed\n");
        exit(1);
    }
    memset(msg, 0xA5, sizeof msg);
}

static void st_keygen(void *unused)
{
    (void)unused;
    if (crypto_sign_keypair(pk, sk) != 0)
        ok = 0;
}

static void st_sign(void *unused)
{
    (void)unused;
    smlen = 0;
    if (crypto_sign(sm, &smlen, msg, sizeof msg, sk) != 0)
        ok = 0;
}

static void st_verify(void *unused)
{
    (void)unused;
    mlen_out = 0;
    if (crypto_sign_open(m_out, &mlen_out, sm, smlen, pk) != 0)
        ok = 0;
}

static void st_teardown(void)
{
    free(pk);
    free(sk);
    free(sm);
    free(m_out);
}

int main(int argc, char **argv)
{
    sp_suite_t suite = {
        .tag = CRYPTO_ALGNAME,
        .setup = st_setup,
        .keygen = st_keygen,
        .sign = st_sign,
        .verify = st_verify,
        .teardown = st_teardown,
        .ok_flag = &ok,
    };
    return sp_probe_main(argc, argv, &suite);
}
