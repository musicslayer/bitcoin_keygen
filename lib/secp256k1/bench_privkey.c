/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

// After building secp256k1_fast_unsafe, compile benchmarks with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ bench_privkey.c timer.c -lgmp -o bench_privkey


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

#define HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"


void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02x ", *chr & 0xFF); }
}


void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}


// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}


const unsigned char baseline_privkey[32] = {
    // generated using srand(31415926), first 256 calls of rand() & 0xFF
    0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
    0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
};

const unsigned char baseline_expected[65] = {
    0x04, 0xfa, 0xf4, 0x5a, 0x13, 0x1f, 0xe3, 0x16, 0xe7, 0x59, 0x78, 0x17, 0xf5, 0x32, 0x14, 0x0d,
    0x75, 0xbb, 0xc2, 0xb7, 0xdc, 0xd6, 0x18, 0x35, 0xea, 0xbc, 0x29, 0xfa, 0x5d, 0x7f, 0x80, 0x25,
    0x51, 0xe5, 0xae, 0x5b, 0x10, 0xcf, 0xc9, 0x97, 0x0c, 0x0d, 0xca, 0xa1, 0xab, 0x7d, 0xc1, 0xb3,
    0x40, 0xbc, 0x5b, 0x3d, 0xf6, 0x87, 0xa5, 0xbc, 0xe7, 0x26, 0x67, 0xfd, 0x6c, 0xe6, 0xc3, 0x66, 0x29
};



int main(int argc, char **argv) {
    unsigned int iter_exp   = ( argc > 1 ? atoi(argv[1]) : 16 );    // Number of iterations as 2^N
    unsigned int bmul_size  = ( argc > 2 ? atoi(argv[2]) : 18 );    // ecmult_big window size in bits
    unsigned int batch_size = ( argc > 3 ? atoi(argv[3]) : 16 );    // ecmult_batch size in keys

    unsigned int iterations = (1 << iter_exp);
    unsigned int total_keys = iterations * batch_size;

    struct timespec clock_start;
    double clock_diff;

    printf("iterations = %u (2^%u)\n", iterations, iter_exp);
    printf("bmul  size = %u\n", bmul_size);
    printf("batch size = %u\n", batch_size);
    printf("total keys = %u\n", total_keys);
    printf("\n");


    // Initializing secp256k1 context
    clock_start = get_clock();
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    clock_diff = get_clockdiff_s(clock_start);
    printf("main context = %12.8f\n", clock_diff);


    // Initializing secp256k1_ecmult_big context
    clock_start = get_clock();
    secp256k1_ecmult_big_context* bmul = secp256k1_ecmult_big_create(ctx, bmul_size);
    clock_diff = get_clockdiff_s(clock_start);
    printf("bmul context = %12.8f\n", clock_diff);
    printf("\n");


    // Initializing secp256k1_scratch for batched key calculations
    secp256k1_scratch *scr = secp256k1_scratch_create(ctx, batch_size);



    ////////////////////////////////////////////////////////////////////////////////
    //                                Verification                                //
    ////////////////////////////////////////////////////////////////////////////////

    size_t test_count = 1024;
    size_t expected_count;
    size_t actual_count;

    // Verify serial pubkey generation
    unsigned char *privkey  = (unsigned char*)safe_calloc(1, 32 * sizeof(unsigned char));
    unsigned char *expected = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));
    unsigned char *actual   = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));


    // Quick baseline test to make sure we can trust our "expected" results
    memcpy(privkey,  baseline_privkey,  32);
    memcpy(expected, baseline_expected, 65);

    expected_count = 1;
    actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, NULL, actual, privkey, 0);

    if ( actual_count != expected_count ) {
        printf("Baseline verification warning\n");
        printf("  expected count = %zu\n", expected_count);
        printf("  actual   count = %zu\n", actual_count);
    }

    if ( memcmp(expected, actual, 65) != 0 ) {
        printf("Baseline verification failed\n");
        printf("  privkey  = "); hex_dump(privkey,  32); printf("\n");
        printf("  expected = "); hex_dump(expected, 65); printf("\n");
        printf("  actual   = "); hex_dump(actual,   65); printf("\n");
        return 1;
    }
    printf("Baseline verification passed\n");


    // Verify that using the faster bmul context returns correct results
    for ( size_t iter = 0; iter < test_count; iter++ ) {
        rand_privkey(privkey);

        // Known working result
        expected_count = secp256k1_ec_pubkey_create_serialized(ctx, NULL, expected, privkey, 0);

        // Method being tested
        actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, bmul, actual,   privkey, 0);


        if ( expected_count != actual_count ) {
            printf("Serial verification warning on iteration %zu\n", iter);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        if ( memcmp(expected, actual, 65) != 0 ) {
            printf("Serial verification failed on iteration %zu\n", iter);
            printf("  privkey  = "); hex_dump(privkey,  32); printf("\n");
            printf("  expected = "); hex_dump(expected, 65); printf("\n");
            printf("  actual   = "); hex_dump(actual,   65); printf("\n");
            return 1;
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Serial verification passed\n");


    // Verify batched pubkey generation
    // If we made it this far, we can trust ecmult_big results, so we'll
    //   use it to make this part of the verification go a little faster
    privkey  = (unsigned char*)safe_calloc(batch_size, 32 * sizeof(unsigned char));
    expected = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));
    actual   = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));

    for ( size_t batch = 0; batch < test_count / batch_size; batch++ ) {
        expected_count = 0;

        for ( size_t i = 0; i < batch_size; i++ ) {
            rand_privkey(&privkey[32 * i]);
            expected_count += secp256k1_ec_pubkey_create_serialized(ctx, bmul, &expected[65 * i], &privkey[32 * i], 0);
        }

        actual_count = secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, actual, privkey, batch_size, 0);


        if ( expected_count != actual_count ) {
            printf("Batch verification warning on batch %zu\n", batch);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        for ( size_t i = 0; i < batch_size; i++ ) {
            unsigned char *p = &( privkey[32 * i]);
            unsigned char *e = &(expected[65 * i]);
            unsigned char *a = &(  actual[65 * i]);

            if ( memcmp(e, a, 65) != 0 ) {
                printf("Batch verification failed on batch %zu item %zu\n", batch, i);
                printf("  privkey  = "); hex_dump(p, 32); printf("\n");
                printf("  expected = "); hex_dump(e, 65); printf("\n");
                printf("  actual   = "); hex_dump(a, 65); printf("\n");
                return 1;
            }
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Batched verification passed\n");
    printf("\n");



    ////////////////////////////////////////////////////////////////////////////////
    //                                 Benchmark                                  //
    ////////////////////////////////////////////////////////////////////////////////

    unsigned char *privkeys = (unsigned char*)safe_calloc(batch_size, 32 * sizeof(unsigned char));
    unsigned char *pubkeys  = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));

    // Get a rough estimate of how long privkey randomization takes
    clock_start = get_clock();
    for ( size_t iter = 0; iter < iterations; iter++ ) {
        rand_privkey(&privkeys[32 * (iter % batch_size)]);
    }
    double privkey_time = get_clockdiff_s(clock_start);


    // Actual benchmark loop
    clock_start = get_clock();
    for ( size_t iter = 0; iter < iterations; iter++ ) {
        for ( size_t b = 0; b < batch_size; b++ ) {
            rand_privkey(&privkeys[32 * b]);
        }

        // Wrapped in if to prevent "ignoring return value" warning
        if ( secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, pubkeys, privkeys, batch_size, 0) );
    }
    double pubkey_time = get_clockdiff_s(clock_start);
    pubkey_time -= (privkey_time * batch_size);


    // Benchmark results
    printf("pubkey total = %12.8f\n", pubkey_time);
    printf("pubkey avg   = %12.8f\n", pubkey_time / total_keys);
    printf("pubkey/sec   = %12.2f\n", total_keys / pubkey_time);
    printf("\n");
    return 0;
}