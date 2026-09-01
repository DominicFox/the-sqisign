/* stack_probe_common.h -- shared driver for the per-primitive stack benchmark.
 */
#ifndef STACK_PROBE_COMMON_H
#define STACK_PROBE_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stackprobe.h"

#define SP_DEFAULT_OUT "sqisign_stack_telemetry.bin"
#define SP_DEFAULT_STACK_MB 64u

typedef struct {
    uint64_t iter;
    uint64_t keygen_stack;
    uint64_t sign_stack;
    uint64_t verify_stack;
    uint64_t keygen_resident;
    uint64_t sign_resident;
    uint64_t verify_resident;
    uint64_t ok; /* 1 if every primitive returned success this iteration */
} sp_row_t;

typedef struct {
    const char *tag;
    void (*setup)(void);    /* allocate/init state; may leave keys ungenerated */
    void (*keygen)(void *);
    void (*sign)(void *);   /* must use the key produced by keygen            */
    void (*verify)(void *); /* must use the signature produced by sign        */
    void (*teardown)(void);
    int *ok_flag;
} sp_suite_t;

static long sp_arg(int argc, char **argv, const char *key, long dflt)
{
    size_t klen = strlen(key);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], key, klen) == 0 && argv[i][klen] == '=')
            return strtol(argv[i] + klen + 1, NULL, 10);
    return dflt;
}

static const char *sp_arg_str(int argc, char **argv, const char *key,
                              const char *dflt)
{
    size_t klen = strlen(key);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], key, klen) == 0 && argv[i][klen] == '=')
            return argv[i] + klen + 1;
    return dflt;
}

static int sp_flag(int argc, char **argv, const char *key)
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], key) == 0)
            return 1;
    return 0;
}


static int sp_probe_main(int argc, char **argv, const sp_suite_t *s)
{
    long iters = sp_arg(argc, argv, "--iterations", 100);
    long stack_mb = sp_arg(argc, argv, "--stack-mb", SP_DEFAULT_STACK_MB);
    const char *out = sp_arg_str(argc, argv, "--out", SP_DEFAULT_OUT);
    int csv = sp_flag(argc, argv, "--csv");
    int no_res = sp_flag(argc, argv, "--no-resident");
    size_t stack_bytes = (size_t)stack_mb << 20;

    if (iters <= 0)
        iters = 1;

    sp_row_t *rows = (sp_row_t *)calloc((size_t)iters, sizeof(sp_row_t));
    if (!rows) {
        fprintf(stderr, "[stack_probe] out of memory\n");
        return 1;
    }

    if (s->setup)
        s->setup();

    if (csv)
        printf("variant,primitive,iter,stack_bytes,resident_bytes,ok\n");

    for (long i = 0; i < iters; i++) {
        if (s->ok_flag)
            *s->ok_flag = 1;

        size_t kg = sp_measure(s->keygen, NULL, stack_bytes);
        size_t kg_r = no_res ? 0 : sp_measure_resident(s->keygen, NULL, stack_bytes);
        size_t sg = sp_measure(s->sign, NULL, stack_bytes);
        size_t sg_r = no_res ? 0 : sp_measure_resident(s->sign, NULL, stack_bytes);
        size_t vf = sp_measure(s->verify, NULL, stack_bytes);
        size_t vf_r = no_res ? 0 : sp_measure_resident(s->verify, NULL, stack_bytes);

        rows[i].iter = (uint64_t)i;
        rows[i].keygen_stack = (uint64_t)kg;
        rows[i].sign_stack = (uint64_t)sg;
        rows[i].verify_stack = (uint64_t)vf;
        rows[i].keygen_resident = (uint64_t)kg_r;
        rows[i].sign_resident = (uint64_t)sg_r;
        rows[i].verify_resident = (uint64_t)vf_r;
        rows[i].ok = (uint64_t)(s->ok_flag ? (*s->ok_flag != 0) : 1);

        if (csv) {
            printf("%s,keygen,%ld,%zu,%zu,%llu\n", s->tag, i, kg, kg_r,
                   (unsigned long long)rows[i].ok);
            printf("%s,sign,%ld,%zu,%zu,%llu\n", s->tag, i, sg, sg_r,
                   (unsigned long long)rows[i].ok);
            printf("%s,verify,%ld,%zu,%zu,%llu\n", s->tag, i, vf, vf_r,
                   (unsigned long long)rows[i].ok);
            fflush(stdout);
        } else if ((i % 10) == 0) {
            printf("    - %s: iteration %ld/%ld (sign high-water %zu B)\n",
                   s->tag, i, iters, sg);
            fflush(stdout);
        }
    }

    if (s->teardown)
        s->teardown();

    FILE *f = fopen(out, "wb");
    if (!f) {
        fprintf(stderr, "[stack_probe] cannot open %s\n", out);
        free(rows);
        return 1;
    }
    fwrite(rows, sizeof(sp_row_t), (size_t)iters, f);
    fclose(f);
    free(rows);
    return 0;
}

#endif /* STACK_PROBE_COMMON_H */
