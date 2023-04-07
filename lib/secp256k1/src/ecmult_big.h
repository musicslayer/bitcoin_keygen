/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_BIG_H_
#define _SECP256K1_ECMULT_BIG_H_

#include <stdint.h>
#include "secp256k1.c"


/* This works the same as the default ecmult_gen table except that:         */
/* 1. No blinding is applied.  This means the first addition can be         */
/*    replaced with a load and zero-value windows can be skipped.           */
/* 2. The window size can be variably defined, trading memory for speed.    */
/* 3. To save space, the ecmult computation converts the privkey scalar     */
/*    to a signed digit form using the algorithm described by Bodo Moller   */
/*    in `Securing Elliptic Curve Point Multiplication Against              */
/*    Side-Channel Attacks` (Vol 2200, Lecture Notes in Computer Science).  */
/*    It's similar to wNAF but with fixed window sizes and it doesn't care  */
/*    if the current window value is odd or even.                           */
/*                                                                          */
/* The final table size will be 64 bytes per table entry.                   */
/* The exact number of table entries is:                                    */
/*     floor(256/bits) * 2^(bits - 1)       [Size of full rows]             */
/*   + 2^(256 % bits)                       [Final smaller row]             */
/*                                                                          */
/* Various window bit sizes and their memory requirements:                  */
/*    4 bits =     <0.1 MB final +   <0.1 MB setup; 65 rows                 */
/*    8 bits =      0.3 MB final +   <0.1 MB setup; 33 rows                 */
/*   10 bits =      0.8 MB final +    0.1 MB setup; 26 rows                 */
/*   12 bits =      2.6 MB final +    0.3 MB setup; 22 rows                 */
/*   14 bits =      9.0 MB final +    1.3 MB setup; 19 rows                 */
/*   16 bits =     32.0 MB final +    5.1 MB setup; 17 rows                 */
/*   17 bits =     60.0 MB final +   10.3 MB setup; 16 rows                 */
/*   18 bits =    112.0 MB final +   20.5 MB setup; 15 rows                 */
/*   19 bits =    208.0 MB final +   41.0 MB setup; 14 rows                 */
/*   20 bits =    388.0 MB final +   82.0 MB setup; 13 rows                 */
/*   21 bits =    768.0 MB final +  164.0 MB setup; 13 rows                 */
/*   22 bits =   1409.0 MB final +  328.0 MB setup; 12 rows                 */
/*   23 bits =   2816.0 MB final +  656.1 MB setup; 12 rows                 */
/*   24 bits =   5124.0 MB final + 1312.2 MB setup; 11 rows                 */
/*                                                                          */
/* The maximum number of addition operations to compute a pubkey is equal   */
/*   to the number of rows in the precomputed table as each row represents  */
/*   all the possible values of a w-bit window of the privkey scalar.       */
/* The actual number of additions may be less as the first window addition  */
/*   is replaced by a load and any zero valued w-bit windows are skipped.   */
typedef struct {
    /* Precomputed window size in bits. */
    const unsigned int bits;

    /* Number of precomputed windows; the precomp table will have this many rows.   */
    const unsigned int windows;

    /* This table will have floor(256/bits) + 1 rows, each with 2^(bits-1) entries. */
    /*                                                                              */
    /* Each row's values will be between {offset, offset + 2^(bits-1)}.             */
    /* Each row's offset will be 2^(bits) times the previous, or 2^(row*bits).      */
    /* Each row's values may be treated as positive or negative, meaning that it    */
    /*   represents 2^(bits) effective values for use in signed digit form.         */
    /* Building upon this, a w-bit window value of N is stored at row[abs(N)-1]     */
    /*   with the the result of row[abs(N)-1] being negated if N is negative.       */
    /* Keep in mind that there are no zero/point at infinity values in precomp.     */
    /*   If a w-bit window is entirely zeroes, that window will be skipped.         */
    /*                                                                              */
    /* The last row will be smaller so that the window stops at the 257th bit.      */
    /* We go to 257 bits instead of 256 to account for a possible high 1 bit after  */
    /*   converting the privkey scalar to a signed digit form.                      */
    /*                                                                              */
    /* We use ge_storage instead of regular ge to save ~25% more space.             */
    secp256k1_ge_storage **precomp;

    /* Holds a single row in the precomputation table before converting to affine.  */
    /* This memory will be freed after creating the precomputation table.           */
    secp256k1_gej *gej_temp;

    /* Holds the Z ratios between each temp row element's Jacobian points.          */
    /* Used to convert to affine with a single field element inversion.             */
    /* This memory will be freed after creating the precomputation table.           */
    secp256k1_fe *z_ratio;
} secp256k1_ecmult_big_context;


/** Create a secp256k1 ecmult big context.
 *
 *  Returns: a newly created ecmult big context.
 *  Args:   ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  In:     bits:   the window size in bits for the precomputation table
 */
SECP256K1_API secp256k1_ecmult_big_context* secp256k1_ecmult_big_create(
    const secp256k1_context* ctx,
    const unsigned int bits
) SECP256K1_WARN_UNUSED_RESULT SECP256K1_ARG_NONNULL(1);


/** Destroy a secp256k1 ecmult big context.
 *
 *  The context pointer may not be used afterwards.
 *  Args:   bmul:   an existing context to destroy (cannot be NULL)
 */
SECP256K1_API void secp256k1_ecmult_big_destroy(
    secp256k1_ecmult_big_context* bmul
) SECP256K1_ARG_NONNULL(1);



/** Shifts and returns the first N <= 64 bits from a scalar.
 *  The default secp256k1_scalar_shr_int only handles up to 15 bits.
 *
 *  Args:   s:      a scalar object to shift from (cannot be NULL)
 *  In:     n:      number of bits to shift off and return
 */
static uint64_t secp256k1_scalar_shr_any(
    secp256k1_scalar *s,
    unsigned int n
) SECP256K1_ARG_NONNULL(1);


/** Converts the lowest w-bit window of scalar s into signed binary form
 *
 *  Returns: signed form of the lowest w-bit window
 *  Args:   s:  scalar to read from and modified (cannot be NULL)
 *  In:     w:  window size in bits (w < 64)
 */
static int64_t secp256k1_scalar_sdigit_single(
    secp256k1_scalar *s,
    unsigned int w
) SECP256K1_ARG_NONNULL(1);


/** Converts s to a signed digit form using w-bit windows.
 *
 *  Returns: number of signed digits written, some digits may be zero
 *  Out:    sdigits:    signed digit representation of s (cannot be NULL)
 *  In:     s:          scalar value to convert to signed digit form
 *          w:          window size in bits
 */
static size_t secp256k1_scalar_sdigit(
    int64_t *sdigits,
    secp256k1_scalar s,
    unsigned int w
) SECP256K1_ARG_NONNULL(1);


/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
static void secp256k1_ecmult_big(
    const secp256k1_ecmult_big_context* bmul,
    secp256k1_gej *r,
    const secp256k1_scalar *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);


#endif