// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <api.h>
#include <rng.h>
#include <bench.h>
#include <bench_test_arguments.h>
#if defined(TARGET_BIG_ENDIAN)
#include <tutil.h>
#endif

typedef struct {
    uint64_t key_index;
    uint64_t keygen_cycles;
    uint64_t sign_cycles;
    uint64_t verify_cycles;
} TelemetryRow;

extern uint64_t cpucycles(void);

void
bench(size_t num_keys, size_t runs_per_key, size_t warmup_runs, int mode)
{
    const size_t m_len = 32;
    const size_t sm_len = CRYPTO_BYTES + m_len;

    // Buffer for the K keys
    unsigned char *pkbuf = calloc(num_keys, CRYPTO_PUBLICKEYBYTES);
    unsigned char *skbuf = calloc(num_keys, CRYPTO_SECRETKEYBYTES);
    unsigned char *pk[num_keys], *sk[num_keys];
    
    for (size_t i = 0; i < num_keys; ++i) {
        pk[i] = pkbuf + i * CRYPTO_PUBLICKEYBYTES;
        sk[i] = skbuf + i * CRYPTO_SECRETKEYBYTES;
    }

    // Buffer for the M runs (reused for each key to save RAM)
    unsigned char *smbuf = calloc(runs_per_key, sm_len);
    unsigned char *mbuf = calloc(runs_per_key, m_len);
    unsigned char *sm[runs_per_key], *m[runs_per_key];

    for (size_t i = 0; i < runs_per_key; ++i) {
        sm[i] = smbuf + i * sm_len;
        m[i] = mbuf + i * m_len;
    }

    unsigned long long len;
    uint64_t start_time, end_time;
    
    TelemetryRow *telemetry_data = NULL;
    size_t rows_to_dump = 0;

    // =====================================================================
    // MODE 0: KEYGEN PROFILE (Generates K keys)
    // =====================================================================
    if (mode == 0) {
        printf("    - Beginning Keygen...\n");
        // --- THE WARMUP PHASE ---
        if (warmup_runs > 0) {
            unsigned char w_pk[CRYPTO_PUBLICKEYBYTES];
            unsigned char w_sk[CRYPTO_SECRETKEYBYTES];
            for (size_t w = 0; w < warmup_runs; ++w) {
                crypto_sign_keypair(w_pk, w_sk); // Math executes, results discarded
            }
        }
        // -------------------------
        
        telemetry_data = calloc(num_keys, sizeof(TelemetryRow));
        rows_to_dump = num_keys;

        for (size_t k = 0; k < num_keys; ++k) {
            start_time = cpucycles();
            crypto_sign_keypair(pk[k], sk[k]);
            end_time = cpucycles();
            
            telemetry_data[k].key_index = k;
            telemetry_data[k].keygen_cycles = (end_time >= start_time) ? (end_time - start_time) : 0;
        }

        FILE *f_pk = fopen("fixed_pk.bin", "wb");
        FILE *f_sk = fopen("fixed_sk.bin", "wb");
        if(f_pk) { fwrite(pkbuf, 1, num_keys * CRYPTO_PUBLICKEYBYTES, f_pk); fclose(f_pk); }
        if(f_sk) { fwrite(skbuf, 1, num_keys * CRYPTO_SECRETKEYBYTES, f_sk); fclose(f_sk); }
        printf("    - Keygen Complete: %zu total keys.\n", num_keys);
    }


    // =====================================================================
    // MODE 1: FIXED KEY, RANDOM MESSAGES 
    // =====================================================================
    if (mode == 1) {
        printf("    - Running Fixed-Key, Random-Message Suite...\n");
        
        // Allocate buffer space for a single batch keypair
        unsigned char pk_single[CRYPTO_PUBLICKEYBYTES];
        unsigned char sk_single[CRYPTO_SECRETKEYBYTES];

        // Generate the unique key pair for THIS specific batch execution
        uint64_t kg_start = cpucycles();
        crypto_sign_keypair(pk_single, sk_single);
        uint64_t kg_end = cpucycles();
        uint64_t batch_keygen_cycles = (kg_end >= kg_start) ? (kg_end - kg_start) : 0;

        // CPU WARMUP (Sign & Verify)
        unsigned char w_msg[32];
        unsigned char w_msg_out[32]; // Dedicated buffer for the recovered message
        unsigned long long sig_len, msg_len;
        
        randombytes(w_msg, 32);
        for(size_t w = 0; w < warmup_runs; ++w) {
            sig_len = sm_len;
            
            // 1. Sign the message using sm[0] (the first allocated buffer pointer)
            crypto_sign(sm[0], &sig_len, w_msg, 32, sk_single); 
            
            // 2. Verify using the ACTUAL signature length (sig_len)
            int ret = crypto_sign_open(w_msg_out, &msg_len, sm[0], sig_len, pk_single);
            
            if (ret != 0) {
                fprintf(stderr, "[-] Mode 1 Warmup verification failed!\n");
                abort();
            }
        }

        size_t total_runs = runs_per_key; 
        telemetry_data = calloc(total_runs, sizeof(TelemetryRow));
        rows_to_dump = total_runs;

        // Roll unique messages for this run
        for (size_t i = 0; i < total_runs; ++i) {
            if (randombytes(m[i], m_len)) abort();
        }

        // Sign loop using the single batch key
        for (size_t i = 0; i < total_runs; ++i) {
            telemetry_data[i].key_index = 0; // Fixed index indicator
            telemetry_data[i].keygen_cycles = batch_keygen_cycles; // Track key setup cost
            
            len = sm_len;
            start_time = cpucycles();
            crypto_sign(sm[i], &len, m[i], m_len, sk_single);
            end_time = cpucycles();
            telemetry_data[i].sign_cycles = (end_time >= start_time) ? (end_time - start_time) : 0;
        }

        // Verify loop
        for (size_t i = 0; i < total_runs; ++i) {
            len = m_len;
            start_time = cpucycles();
            int ret = crypto_sign_open(m[i], &len, sm[i], sm_len, pk_single);
            end_time = cpucycles();
            if (ret) abort();
            telemetry_data[i].verify_cycles = (end_time >= start_time) ? (end_time - start_time) : 0;
        }

        // DUMP MODE 1 BATCH VARIABLES TO DISK
        FILE *f_bpk = fopen("batch_pk.bin", "wb");
        if(f_bpk) { fwrite(pk_single, 1, CRYPTO_PUBLICKEYBYTES, f_bpk); fclose(f_bpk); }

        FILE *f_bsk = fopen("batch_sk.bin", "wb");
        if(f_bsk) { fwrite(sk_single, 1, CRYPTO_SECRETKEYBYTES, f_bsk); fclose(f_bsk); }

        FILE *f_bmsg = fopen("batch_messages.bin", "wb");
        if(f_bmsg) { 
            for (size_t i = 0; i < total_runs; ++i) {
                fwrite(m[i], 1, m_len, f_bmsg);
            }
            fclose(f_bmsg); 
        }

        printf("    - Batch Run Complete: %zu messages processed.\n", total_runs);
    }

    // =====================================================================
    // MODE 2: FIXED MESSAGE, RANDOM KEYS
    // =====================================================================
    if (mode == 2) {
        printf("    - Running Fixed-Message, Random-Key Suite...\n");

        // CPU WARMUP (Keygen, Sign & Verify)
        unsigned char w_msg[32], w_msg_out[32], w_pk[CRYPTO_PUBLICKEYBYTES], w_sk[CRYPTO_SECRETKEYBYTES];
        unsigned long long sig_len, msg_len;
        
        randombytes(w_msg, 32);
        for(size_t w = 0; w < warmup_runs; ++w) {
            // 1. Generate the temporary keypair
            crypto_sign_keypair(w_pk, w_sk);
            
            // 2. Sign using sm[0]
            sig_len = sm_len;
            crypto_sign(sm[0], &sig_len, w_msg, 32, w_sk);
            
            // 3. Verify
            int ret = crypto_sign_open(w_msg_out, &msg_len, sm[0], sig_len, w_pk);
            
            if (ret != 0) {
                fprintf(stderr, "[-] Mode 2 Warmup verification failed!\n");
                abort();
            }
        }
        
        size_t total_runs = num_keys;
        telemetry_data = calloc(total_runs, sizeof(TelemetryRow));
        rows_to_dump = total_runs;

        // Generate a FRESH static message challenge for THIS batch execution
        unsigned char static_msg[32];
        if (randombytes(static_msg, m_len)) abort();

        for (size_t k = 0; k < total_runs; ++k) {
            telemetry_data[k].key_index = k;

            // Generate a new key pair for every single signature iteration
            uint64_t kg_start = cpucycles();
            crypto_sign_keypair(pk[k], sk[k]); // Stored safely in pkbuf / skbuf
            uint64_t kg_end = cpucycles();
            telemetry_data[k].keygen_cycles = (kg_end >= kg_start) ? (kg_end - kg_start) : 0;

            // Sign the fixed challenge string
            len = sm_len;
            start_time = cpucycles();
            crypto_sign(sm[0], &len, static_msg, m_len, sk[k]);
            end_time = cpucycles();
            telemetry_data[k].sign_cycles = (end_time >= start_time) ? (end_time - start_time) : 0;

            // Verify
            len = m_len;
            start_time = cpucycles();
            int ret = crypto_sign_open(m[0], &len, sm[0], sm_len, pk[k]);
            end_time = cpucycles();
            if (ret) abort();
            telemetry_data[k].verify_cycles = (end_time >= start_time) ? (end_time - start_time) : 0;
        }

        // Dump all 1,000 keys and the single static message to SSD for Rust
        FILE *f_bpk = fopen("batch_pk.bin", "wb");
        if(f_bpk) { fwrite(pkbuf, 1, total_runs * CRYPTO_PUBLICKEYBYTES, f_bpk); fclose(f_bpk); }

        FILE *f_bsk = fopen("batch_sk.bin", "wb");
        if(f_bsk) { fwrite(skbuf, 1, total_runs * CRYPTO_SECRETKEYBYTES, f_bsk); fclose(f_bsk); }

        FILE *f_bmsg = fopen("batch_msg_single.bin", "wb");
        if(f_bmsg) { fwrite(static_msg, 1, m_len, f_bmsg); fclose(f_bmsg); }

        printf("    - Batch Run Complete: %zu keys evaluated against fresh static message.\n", total_runs);
    }

    // EXPORT RAW BINARY TELEMETRY DATA
    FILE *fp = fopen("sqisign_telemetry.bin", "wb");
    if (fp != NULL && telemetry_data != NULL) {
        fwrite(telemetry_data, sizeof(TelemetryRow), rows_to_dump, fp);
        fclose(fp);
        // printf("    - Dumped %zu telemetry rows to 'sqisign_telemetry.bin'\n", rows_to_dump);
    }

    if (telemetry_data) free(telemetry_data);
    free(pkbuf);
    free(skbuf);
    free(smbuf);
    free(mbuf);
}

int
main(int argc, char *argv[])
{
    int iterations = SQISIGN_TEST_REPS; 
    int num_keys = 100;                 
    int warmup_runs = 10; 
    int mode = 0;                       
    int help = 0;

#ifndef NDEBUG
    fprintf(stderr,
            "\x1b[31mIt looks like SQIsign was compiled with assertions enabled.\n"
            "This will severely impact performance measurements.\x1b[0m\n");
#endif

    for (int i = 1; i < argc; i++) {
        if (!help && strcmp(argv[i], "--help") == 0) { help = 1; continue; }
        if (sscanf(argv[i], "--iterations=%d", &iterations) == 1) continue;
        if (sscanf(argv[i], "--keys=%d", &num_keys) == 1) continue;
        if (sscanf(argv[i], "--warmup=%d", &warmup_runs) == 1) continue;
        
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            if (strcmp(argv[i] + 7, "keygen") == 0 || strcmp(argv[i] + 7, "0") == 0) mode = 0;
            else if (strcmp(argv[i] + 7, "fixed_key") == 0 || strcmp(argv[i] + 7, "1") == 0) mode = 1;
            else if (strcmp(argv[i] + 7, "fixed_msg") == 0 || strcmp(argv[i] + 7, "2") == 0) mode = 2;
            continue;
        }
    }

    if (help || iterations <= 0 || num_keys <= 0) {
        printf("Usage: %s [--keys=<outer_loop>] [--iterations=<inner_loop>] [--warmup=<burn_in>] [--mode=<0|1|2>]\n", argv[0]);
        return 1;
    }

    // Hardware entropy is handled by macOS. Only initialize the timer.
    cpucycles_init();

    // Pass the parameters to the benchmarking harness
    bench(num_keys, iterations, warmup_runs, mode);

    return 0;
}