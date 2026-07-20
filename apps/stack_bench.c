// stack_bench.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include the SQISign API header (adjust path as needed for your repo)
#include "api.h" 

// Helper function: Convert hex string to heap-allocated byte array
// We use the heap (malloc) to keep the stack absolutely flat
uint8_t* hex_to_bytes(const char* hex_string, size_t* out_len) {
    size_t len = strlen(hex_string);
    *out_len = len / 2;
    uint8_t* bytes = (uint8_t*)malloc(*out_len);
    
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex_string + 2*i, "%2hhx", &bytes[i]);
    }
    return bytes;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 1;
    }

    size_t key_len, raw_msg_len;
    
    // Parse arguments onto the HEAP
    uint8_t* secret_key = hex_to_bytes(argv[1], &key_len);
    uint8_t* message = hex_to_bytes(argv[2], &raw_msg_len);
    
    // Cast the message length to the NIST-required type
    unsigned long long msg_len = (unsigned long long)raw_msg_len;
    
    // Allocate space for the signature and its length on the HEAP
    size_t sig_max_len = CRYPTO_BYTES; 
    uint8_t* signature = (uint8_t*)malloc(sig_max_len);
    
    // Declare sig_len as unsigned long long to satisfy the NIST pointer requirement
    unsigned long long sig_len = 0;

    // --- THE MEASUREMENT ZONE ---
    // At this exact moment, the stack is almost perfectly empty.
    // The only thing that will push the %rsp pointer down is this function call.
    
    int result = crypto_sign(signature, &sig_len, message, msg_len, secret_key);
    
    // --- END MEASUREMENT ZONE ---

    // Clean up heap memory (Valgrind appreciates good hygiene)
    free(secret_key);
    free(message);
    free(signature);

    return result;
}