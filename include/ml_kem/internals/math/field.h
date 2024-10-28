#ifndef ML_KEM_FIELD_H
#define ML_KEM_FIELD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

// Assuming ml_kem_prng.h is available
#include "ml_kem_prng.h"

// Ml_kem Prime Field Modulus ( = 3329 )
#define Q ((1u << 8) * 13 + 1)

// Bit width of Ml_kem Prime Field Modulus ( = 12 )
#define Q_BIT_WIDTH 12

// Precomputed Barrett Reduction Constant
#define R ((1u << (2 * Q_BIT_WIDTH)) / Q)

typedef struct {
    uint32_t v;
} zq_t;

static inline uint32_t reduce_once(uint32_t v) {
    uint32_t t0 = v - Q;
    uint32_t t1 = -(t0 >> 31);
    uint32_t t2 = Q & t1;
    uint32_t t3 = t0 + t2;
    return t3;
}

static inline uint32_t barrett_reduce(uint32_t v) {
    uint64_t t0 = (uint64_t)v * (uint64_t)R;
    uint32_t t1 = (uint32_t)(t0 >> (2 * Q_BIT_WIDTH));
    uint32_t t2 = t1 * Q;
    uint32_t t = v - t2;
    return reduce_once(t);
}

static inline zq_t zq_init(uint16_t a) {
    zq_t result = {.v = a};
    return result;
}

static inline zq_t zq_from_non_reduced(uint16_t a) {
    zq_t result = {.v = barrett_reduce(a)};
    return result;
}

static inline uint32_t zq_raw(const zq_t *z) {
    return z->v;
}

static inline zq_t zq_zero(void) {
    return zq_init(0);
}

static inline zq_t zq_one(void) {
    return zq_init(1);
}

static inline zq_t zq_add(const zq_t *a, const zq_t *b) {
    zq_t result = {.v = reduce_once(a->v + b->v)};
    return result;
}

static inline zq_t zq_neg(const zq_t *a) {
    zq_t result = {.v = Q - a->v};
    return result;
}

static inline zq_t zq_sub(const zq_t *a, const zq_t *b) {
    zq_t neg_b = zq_neg(b);
    return zq_add(a, &neg_b);
}

static inline zq_t zq_mul(const zq_t *a, const zq_t *b) {
    zq_t result = {.v = barrett_reduce(a->v * b->v)};
    return result;
}

static inline zq_t zq_pow(const zq_t *base, size_t n) {
    zq_t result = zq_one();
    zq_t current = *base;

    while (n > 0) {
        if (n & 1) {
            result = zq_mul(&result, &current);
        }
        current = zq_mul(&current, &current);
        n >>= 1;
    }

    return result;
}

static inline zq_t zq_inv(const zq_t *a) {
    return zq_pow(a, Q - 2);
}

static inline zq_t zq_div(const zq_t *a, const zq_t *b) {
    zq_t inv_b = zq_inv(b);
    return zq_mul(a, &inv_b);
}

static inline bool zq_eq(const zq_t *a, const zq_t *b) {
    return a->v == b->v;
}

static inline bool zq_lt(const zq_t *a, const zq_t *b) {
    return a->v < b->v;
}

static inline bool zq_gt(const zq_t *a, const zq_t *b) {
    return a->v > b->v;
}

static inline bool zq_le(const zq_t *a, const zq_t *b) {
    return a->v <= b->v;
}

static inline bool zq_ge(const zq_t *a, const zq_t *b) {
    return a->v >= b->v;
}

// Assuming ml_kem_prng_t is defined in ml_kem_prng.h
zq_t zq_random(ml_kem_prng_t *prng) {
    uint16_t res = 0;
    ml_kem_prng_read(prng, (uint8_t*)&res, sizeof(res));
    return zq_from_non_reduced((uint32_t)res);
}

#endif // ML_KEM_FIELD_H

