#include "../include/ml_kem/ml_kem_768.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

static inline void to_hex(const uint8_t* bytes, size_t length, char* output) {
    for (size_t i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", bytes[i]);
    }
}

// Compile it with
//
// gcc -o ml_kem_768 ml_kem_768.c -I ./include -I ./sha3/include -I ./subtle/include

int main() {
    // Seeds required for keypair generation
    uint8_t d[ml_kem_768_SEED_D_BYTE_LEN] = {0};
    uint8_t z[ml_kem_768_SEED_Z_BYTE_LEN] = {0};

    // Public/ private keypair
    uint8_t pkey[ml_kem_768_PKEY_BYTE_LEN] = {0};
    uint8_t skey[ml_kem_768_SKEY_BYTE_LEN] = {0};

    // Seed required for key encapsulation
    uint8_t m[ml_kem_768_SEED_M_BYTE_LEN] = {0};
    uint8_t cipher[ml_kem_768_CIPHER_TEXT_BYTE_LEN] = {0};

    // Shared secret that sender/ receiver arrives at
    uint8_t sender_key[ml_kem_768_SHARED_SECRET_BYTE_LEN] = {0};
    uint8_t receiver_key[ml_kem_768_SHARED_SECRET_BYTE_LEN] = {0};

    // Pseudo-randomness source
    ml_kem_prng_prng_t prng;
    ml_kem_prng_init(&prng);

    // Fill up seeds using PRNG
    ml_kem_prng_read(&prng, d, sizeof(d));
    ml_kem_prng_read(&prng, z, sizeof(z));

    // Generate a keypair
    ml_kem_768_keygen(d, z, pkey, skey);

    // Fill up seed required for key encapsulation, using PRNG
    ml_kem_prng_read(&prng, m, sizeof(m));

    // Encapsulate key, compute cipher text and obtain KDF
    bool is_encapsulated = ml_kem_768_encapsulate(m, pkey, cipher, sender_key);
    // Decapsulate cipher text and obtain KDF
    ml_kem_768_decapsulate(skey, cipher, receiver_key);

    // Check that both of the communicating parties arrived at same shared secret key
    if (memcmp(sender_key, receiver_key, sizeof(sender_key)) != 0) {
        fprintf(stderr, "Shared secrets do not match!\n");
        return EXIT_FAILURE;
    }

    char pkey_hex[2 * ml_kem_768_PKEY_BYTE_LEN + 1];
    char skey_hex[2 * ml_kem_768_SKEY_BYTE_LEN + 1];
    char cipher_hex[2 * ml_kem_768_CIPHER_TEXT_BYTE_LEN + 1];
    char sender_key_hex[2 * ml_kem_768_SHARED_SECRET_BYTE_LEN + 1];

    to_hex(pkey, sizeof(pkey), pkey_hex);
    to_hex(skey, sizeof(skey), skey_hex);
    to_hex(cipher, sizeof(cipher), cipher_hex);
    to_hex(sender_key, sizeof(sender_key), sender_key_hex);

    printf("ML-KEM-768\n");
    printf("Pubkey         : %s\n", pkey_hex);
    printf("Seckey         : %s\n", skey_hex);
    printf("Encapsulated ? : %s\n", is_encapsulated ? "true" : "false");
    printf("Cipher         : %s\n", cipher_hex);
    printf("Shared secret  : %s\n", sender_key_hex);

    return EXIT_SUCCESS;
}

