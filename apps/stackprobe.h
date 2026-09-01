/* stackprobe.h -- measure the stack high-water mark of a single function call.
 */
#ifndef STACKPROBE_H
#define STACKPROBE_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SP_PATTERN 0xC0FFEEBADDEADBEDULL
#define SP_MARGIN 0

typedef struct {
    void (*fn)(void *);
    void *arg;
    uintptr_t lo;         /* lowest usable stack address (just above guard) */
    uintptr_t paint_top;  /* SP at paint time == zero point of measurement   */
    size_t used;          /* out: bytes of stack consumed by fn              */
    int saturated;        /* out: 1 if fn reached the bottom of the paint    */
} sp_ctx;

/* Current stack pointer.*/
__attribute__((always_inline)) static inline uintptr_t sp_current(void)
{
#if defined(__aarch64__)
    uintptr_t s;
    __asm__ volatile("mov %0, sp" : "=r"(s));
    return s;
#elif defined(__x86_64__)
    uintptr_t s;
    __asm__ volatile("mov %%rsp, %0" : "=r"(s));
    return s;
#else
    volatile char probe;
    return (uintptr_t)&probe;
#endif
}

static void *sp_thread(void *p)
{
    sp_ctx *c = (sp_ctx *)p;
    uintptr_t sp = sp_current();
    uint64_t *top = (uint64_t *)((sp - SP_MARGIN) & ~(uintptr_t)7);
    uint64_t *bot = (uint64_t *)c->lo;

    c->paint_top = (uintptr_t)top;
    for (uint64_t *q = bot; q < top; q++)
        *q = SP_PATTERN;

    c->fn(c->arg);

    uint64_t *lowest = top;
    for (uint64_t *q = bot; q < top; q++) {
        if (*q != SP_PATTERN) {
            lowest = q;
            break;
        }
    }
    c->saturated = (lowest == bot);
    c->used = (size_t)((uintptr_t)top - (uintptr_t)lowest);
    return NULL;
}

/* Returns bytes of stack used by fn(arg) */
static size_t sp_measure(void (*fn)(void *), void *arg, size_t stack_bytes)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);            /* 16384 on arm64 */
    size_t stack = (stack_bytes + pg - 1) & ~(pg - 1);
    size_t total = stack + pg;                            /* + guard page   */

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED)
        return (size_t)-1;
    if (mprotect(base, pg, PROT_NONE) != 0) {             /* guard at bottom */
        munmap(base, total);
        return (size_t)-1;
    }

    sp_ctx c = { .fn = fn, .arg = arg, .lo = (uintptr_t)base + pg,
                 .used = 0, .saturated = 0 };

    pthread_attr_t at;
    pthread_attr_init(&at);
    /* setstack disables the automatic guard page, hence the manual one above */
    pthread_attr_setstack(&at, (char *)base + pg, stack);

    pthread_t th;
    int rc = pthread_create(&th, &at, sp_thread, &c);
    pthread_attr_destroy(&at);
    if (rc != 0) {
        munmap(base, total);
        return (size_t)-1;
    }
    pthread_join(th, NULL);
    munmap(base, total);

    if (c.saturated) {
        fprintf(stderr, "[stackprobe] SATURATED: raise stack_bytes above %zu\n",
                stack);
        return (size_t)-1;
    }
    return c.used;
}

/* Companion metric: no painting; count pages touched in physical memory (resident set size) */
typedef struct { void (*fn)(void *); void *arg; } sp_rctx;

static void *sp_thread_raw(void *p)
{
    sp_rctx *c = (sp_rctx *)p;
    c->fn(c->arg);
    return NULL;
}

static size_t sp_measure_resident(void (*fn)(void *), void *arg,
                                  size_t stack_bytes)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t stack = (stack_bytes + pg - 1) & ~(pg - 1);
    size_t total = stack + pg;

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED)
        return (size_t)-1;
    mprotect(base, pg, PROT_NONE);

    sp_rctx c = { fn, arg };
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstack(&at, (char *)base + pg, stack);
    pthread_t th;
    if (pthread_create(&th, &at, sp_thread_raw, &c) != 0) {
        pthread_attr_destroy(&at);
        munmap(base, total);
        return (size_t)-1;
    }
    pthread_attr_destroy(&at);
    pthread_join(th, NULL);

    size_t npg = stack / pg, touched = 0;
    char *vec = (char *)malloc(npg);
    if (vec && mincore((char *)base + pg, stack, vec) == 0)
        for (size_t i = 0; i < npg; i++)
            if (vec[i] & 1)
                touched++;
    free(vec);
    munmap(base, total);
    return touched * pg;
}

#endif /* STACKPROBE_H */
