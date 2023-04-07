/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_BIG_IMPL_H_
#define _SECP256K1_ECMULT_BIG_IMPL_H_


#include <stddef.h>
#include <stdint.h>
#include "secp256k1.c"
#include "ecmult_big.h"



/** Create a secp256k1 ecmult big context.
 *
 *  Returns: a newly created ecmult big context.
 *  Args:   ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  In:     bits:   the window size in bits for the precomputation table
 */
secp256k1_ecmult_big_context* secp256k1_ecmult_big_create(const secp256k1_context* ctx, const unsigned int bits) {
    unsigned int windows;
    size_t window_size, total_size;
    size_t i, row;

    secp256k1_fe  fe_zinv;
    secp256k1_ge  ge_temp;
    secp256k1_ge  ge_window_one = secp256k1_ge_const_g;
    secp256k1_gej gej_window_base;
    secp256k1_ecmult_big_context *rtn;


    /* No point using fewer bits than the default implementation. */
    ARG_CHECK(bits >=  4);

    /* Each signed digit result must fit in a int64_t, we can't be larger.      */
    /* We also possibly subtract (1 << bits) and can't shift into the sign bit. */
    ARG_CHECK(bits <= 62);

    /* We +1 to account for a possible high 1 bit after converting the privkey to signed digit form.    */
    /* This means our table reaches to 257 bits even though the privkey scalar is at most 256 bits.     */
    windows = (256 / bits) + 1;
    window_size = (1 << (bits - 1));

    /* Total number of required point storage elements.                                 */
    /* This differs from the (windows * window_size) because the last row can be shrunk */
    /*   as it only needs to extend enough to include a possible 1 in the 257th bit.    */
    total_size = (256 / bits) * window_size + (1 << (256 % bits));



    /**************** Allocate Struct Members *****************/
    rtn = (secp256k1_ecmult_big_context *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ecmult_big_context));
    *(unsigned int *)(&rtn->bits) = bits;
    *(unsigned int *)(&rtn->windows) = windows;

    /* An array of secp256k1_ge_storage pointers, one for each window. */
    rtn->precomp = (secp256k1_ge_storage **)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage *) * windows);

    /* Bulk allocate up front.  We'd rather run out of memory now than during computation.  */
    /* Only the 0th row is malloc'd, the rest will be updated to point to row starts        */
    /*   within the giant chunk of memory that we've allocated.                             */
    rtn->precomp[0] = (secp256k1_ge_storage *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage) * total_size);

    /* Each row starts window_size elements after the previous. */
    for ( i = 1; i < windows; i++ ) { rtn->precomp[i] = (rtn->precomp[i - 1] + window_size); }

    rtn->gej_temp = (secp256k1_gej *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * window_size);
    rtn->z_ratio  = (secp256k1_fe  *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * window_size);



    /************ Precomputed Table Initialization ************/
    secp256k1_gej_set_ge(&gej_window_base, &ge_window_one);

    /* This is the same for all windows.    */
    secp256k1_fe_set_int(&(rtn->z_ratio[0]), 0);


    for ( row = 0; row < windows; row++ ) {
        /* The last row is a bit smaller, only extending to include the 257th bit. */
        window_size = ( row == windows - 1 ? (1 << (256 % bits)) : (1 << (bits - 1)) );

        /* The base element of each row is 2^bits times the previous row's base. */
        if ( row > 0 ) {
            for ( i = 0; i < bits; i++ ) { secp256k1_gej_double_var(&gej_window_base, &gej_window_base, NULL); }
        }
        rtn->gej_temp[0] = gej_window_base;

        /* The base element is also our "one" value for this row.   */
        /* If we are at offset 2^X, adding "one" should add 2^X.    */
        secp256k1_ge_set_gej(&ge_window_one, &gej_window_base);


        /* Repeated + 1s to fill the rest of the row.   */

        /* We capture the Z ratios between consecutive points for quick Z inversion.    */
        /*   gej_temp[i-1].z * z_ratio[i] => gej_temp[i].z                              */
        /* This means that z_ratio[i] = (gej_temp[i-1].z)^-1 * gej_temp[i].z            */
        /* If we know gej_temp[i].z^-1, we can get gej_temp[i-1].z^1 using z_ratio[i]   */
        /* Visually:                                    */
        /* i            0           1           2       */
        /* gej_temp     a           b           c       */
        /* z_ratio     NaN      (a^-1)*b    (b^-1)*c    */
        for ( i = 1; i < window_size; i++ ) {
            secp256k1_gej_add_ge_var(&(rtn->gej_temp[i]), &(rtn->gej_temp[i-1]), &ge_window_one, &(rtn->z_ratio[i]));
        }


        /* An unpacked version of secp256k1_ge_set_table_gej_var() that works   */
        /*   element by element instead of requiring a secp256k1_ge *buffer.    */

        /* Invert the last Z coordinate manually.   */
        i = window_size - 1;
        secp256k1_fe_inv(&fe_zinv, &(rtn->gej_temp[i].z));
        secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i]), &fe_zinv);
        secp256k1_ge_to_storage(&(rtn->precomp[row][i]), &ge_temp);

        /* Use the last element's known Z inverse to determine the previous' Z inverse. */
        for ( ; i > 0; i-- ) {
            /* fe_zinv = (gej_temp[i].z)^-1                 */
            /* (gej_temp[i-1].z)^-1 = z_ratio[i] * fe_zinv  */
            secp256k1_fe_mul(&fe_zinv, &fe_zinv, &(rtn->z_ratio[i]));
            /* fe_zinv = (gej_temp[i-1].z)^-1               */

            secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i-1]), &fe_zinv);
            secp256k1_ge_to_storage(&(rtn->precomp[row][i-1]), &ge_temp);
        }
    }


    /* We won't be using these any more.    */
    free(rtn->gej_temp); rtn->gej_temp = NULL;
    free(rtn->z_ratio);  rtn->z_ratio  = NULL;

    return rtn;
}


/** Destroy a secp256k1 ecmult big context.
 *
 *  The context pointer may not be used afterwards.
 *  Args:   bmul:   an existing context to destroy (cannot be NULL)
 */
void secp256k1_ecmult_big_destroy(secp256k1_ecmult_big_context* bmul) {
    VERIFY_CHECK(bmul != NULL);
    if ( bmul == NULL ) { return; }

    /* Just in case the caller tries to use after free. */
    *(unsigned int *)(&bmul->bits)    = 0;
    *(unsigned int *)(&bmul->windows) = 0;

    if ( bmul->precomp != NULL ) {
        /* This was allocated with a single malloc, it will be freed with a single free. */
        if ( bmul->precomp[0] != NULL ) { free(bmul->precomp[0]); bmul->precomp[0] = NULL; }

        free(bmul->precomp); bmul->precomp = NULL;
    }

    /* These should already be freed, but just in case. */
    if ( bmul->gej_temp != NULL ) { free(bmul->gej_temp); bmul->gej_temp = NULL; }
    if ( bmul->z_ratio  != NULL ) { free(bmul->z_ratio ); bmul->z_ratio  = NULL; }

    free(bmul);
}



/** Shifts and returns the first N <= 64 bits from a scalar.
 *  The default secp256k1_scalar_shr_int only handles up to 15 bits.
 *
 *  Args:   s:      a scalar object to shift from (cannot be NULL)
 *  In:     n:      number of bits to shift off and return
 */
uint64_t secp256k1_scalar_shr_any(secp256k1_scalar *s, unsigned int n) {
    unsigned int cur_shift = 0, offset = 0;
    uint64_t rtn = 0;

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(n >   0);
    VERIFY_CHECK(n <= 64);

    while ( n > 0 ) {
        /* Shift up to 15 bits at a time, or N bits, whichever is smaller.  */
        /* secp256k1_scalar_shr_int() is hard limited to (0 < n < 16).      */
        cur_shift = ( n > 15 ? 15 : n );

        rtn |= ((uint64_t)secp256k1_scalar_shr_int(s, cur_shift) << (uint64_t)offset);

        offset += cur_shift;
        n      -= cur_shift;
    }

    return rtn;
}


/** Converts the lowest w-bit window of scalar s into signed binary form
 *
 *  Returns: signed form of the lowest w-bit window
 *  Args:   s:  scalar to read from and modified (cannot be NULL)
 *  In:     w:  window size in bits (w < 64)
 */
static int64_t secp256k1_scalar_sdigit_single(secp256k1_scalar *s, unsigned int w) {
    int64_t sdigit = 0;

    /* Represents a 1 bit in the next window's least significant bit.       */
    /* VERIFY_CHECK verifies that (1 << w) won't touch int64_t's sign bit.  */
    int64_t overflow_bit = (int64_t)(1 << w);

    /* Represents the maximum positive value in a w-bit precomp table.  */
    /* Values greater than this are converted to negative values and    */
    /*   will "reverse borrow" a bit from the next window.              */
    int64_t precomp_max = (int64_t)(1 << (w-1));

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(w >=  1);
    VERIFY_CHECK(w <= 62);

    sdigit = (int64_t)secp256k1_scalar_shr_any(s, w);

    if ( sdigit <= precomp_max ) {
        /* A w-bit precomp table has this digit as a positive value, return as-is.  */
        return sdigit;

    } else {
        secp256k1_scalar one;
        secp256k1_scalar_set_int(&one, 1);

        /* Convert this digit to a negative value, but balance s by adding it's value.  */
        /* Subtracting our sdigit value carries over into a 1 bit of the next digit.    */
        /* Since s has been shifted down w bits, s += 1 does the same thing.            */
        sdigit -= overflow_bit;

        secp256k1_scalar_add(s, s, &one);

        return sdigit;
    }
}


/** Converts s to a signed digit form using w-bit windows.
 *
 *  Returns: number of signed digits written, some digits may be zero
 *  Out:    sdigits:    signed digit representation of s (cannot be NULL)
 *  In:     s:          scalar value to convert to signed digit form
 *          w:          window size in bits
 */
static size_t secp256k1_scalar_sdigit(int64_t *sdigits, secp256k1_scalar s, unsigned int w) {
    size_t digits = 0;

    VERIFY_CHECK(sdigits != NULL);
    VERIFY_CHECK(w >=  1);
    VERIFY_CHECK(w <= 62);

    while ( !secp256k1_scalar_is_zero(&s) ) {
        sdigits[digits] = secp256k1_scalar_sdigit_single(&s, w);
        digits++;
    }

    return digits;
}



/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
static void secp256k1_ecmult_big(const secp256k1_ecmult_big_context* bmul, secp256k1_gej *r, const secp256k1_scalar *a) {
    size_t  window = 0;
    int64_t sdigit = 0;
    secp256k1_ge window_value;

    /* Copy of the input scalar which secp256k1_scalar_sdigit_single will destroy. */
    secp256k1_scalar privkey = *a;

    VERIFY_CHECK(bmul != NULL);
    VERIFY_CHECK(bmul->bits > 0);
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);

    /* Until we hit a non-zero window, the value of r is undefined. */
    secp256k1_gej_set_infinity(r);

    /* If the privkey is zero, bail. */
    if ( secp256k1_scalar_is_zero(&privkey) ) { return; }


    /* Incrementally convert the privkey into signed digit form, one window at a time. */
    while ( window < bmul->windows && !secp256k1_scalar_is_zero(&privkey) ) {
        sdigit = secp256k1_scalar_sdigit_single(&privkey, bmul->bits);

        /* Zero windows have no representation in our precomputed table. */
        if ( sdigit != 0 ) {
            if ( sdigit < 0 ) {
                /* Use the positive precomp index and negate the result. */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ -(sdigit) - 1 ]));
                secp256k1_ge_neg(&window_value, &window_value);
            } else {
                /* Use the precomp index and result as-is.  */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ +(sdigit) - 1 ]));
            }

            /* The first addition is automatically replaced by a load when r = inf. */
            secp256k1_gej_add_ge_var(r, r, &window_value, NULL);
        }

        window++;
    }

    /* If privkey isn't zero, something broke.  */
    VERIFY_CHECK(secp256k1_scalar_is_zero(&privkey));
}


#endif