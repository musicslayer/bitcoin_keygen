/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BATCH_IMPL_H_
#define _SECP256K1_BATCH_IMPL_H_

#include <stddef.h>
#include "secp256k1.c"
#include "secp256k1_batch.h"
#include "ecmult_big.h"


/* Scratch space for secp256k1_ec_pubkey_create_batch's temporary results. */
struct secp256k1_scratch_struct {
    /* Maximum number of elements this scratch space can hold. */
    const size_t size;

    /* Output from individual secp256k1_ecmult_gen. */
    secp256k1_gej *gej;

    /* Input and output buffers for secp256k1_fe_inv_all_var. */
    secp256k1_fe  *fe_in;
    secp256k1_fe  *fe_out;
};


secp256k1_scratch* secp256k1_scratch_create(const secp256k1_context* ctx, const size_t size) {
    secp256k1_scratch* rtn = (secp256k1_scratch *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_scratch));

    /* Cast away const-ness to set the size value.  */
    /* http://stackoverflow.com/a/9691556/477563    */
    *(size_t *)&rtn->size = size;

    rtn->gej    = (secp256k1_gej*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * size);
    rtn->fe_in  = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);
    rtn->fe_out = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);

    return rtn;
}


void secp256k1_scratch_destroy(secp256k1_scratch* scr) {
    if (scr != NULL) {
        /* Just in case the caller tries to reuse this scratch space, set size to zero.     */
        /* Functions that use this scratch space will reject scratches that are undersized. */
        *(size_t *)&scr->size = 0;

        if ( scr->gej    != NULL ) { free(scr->gej   ); scr->gej    = NULL; }
        if ( scr->fe_in  != NULL ) { free(scr->fe_in ); scr->fe_in  = NULL; }
        if ( scr->fe_out != NULL ) { free(scr->fe_out); scr->fe_out = NULL; }

        free(scr);
    }
}



size_t secp256k1_ec_pubkey_create_serialized(const secp256k1_context *ctx, const secp256k1_ecmult_big_context *bmul, unsigned char *pubkey, const unsigned char *privkey, const unsigned int compressed) {
    /* Creating our own 1 element scratch structure. */
    secp256k1_gej gej;
    secp256k1_fe  fe_in, fe_out;
    secp256k1_scratch scr = {1, &gej, &fe_in, &fe_out};

    /* Defer the actual work to _batch, no point repeating code. */
    return secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, &scr, pubkey, privkey, 1, compressed);
}


size_t secp256k1_ec_pubkey_create_serialized_batch(const secp256k1_context *ctx, const secp256k1_ecmult_big_context *bmul, secp256k1_scratch *scr, unsigned char *pubkeys, const unsigned char *privkeys, const size_t key_count, const unsigned int compressed) {
    secp256k1_scalar s_privkey;
    secp256k1_ge ge_pubkey;
    size_t i, dummy, out_keys;
    size_t pubkey_size = ( compressed ? 33 : 65 );

    /* Argument checking. */
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    ARG_CHECK(scr         != NULL);
    ARG_CHECK(scr->gej    != NULL);
    ARG_CHECK(scr->fe_in  != NULL);
    ARG_CHECK(scr->fe_out != NULL);

    ARG_CHECK(pubkeys  != NULL);

    ARG_CHECK(privkeys != NULL);

    ARG_CHECK(key_count <= scr->size);


    /* Blank all of the output, regardless of what happens.                 */
    /* This marks all output keys as invalid until successfully created.    */
    memset(pubkeys, 0, sizeof(*pubkeys) * pubkey_size * key_count);

    out_keys = 0;

    for ( i = 0; i < key_count; i++ ) {
        /* Convert private key to scalar form. */
        secp256k1_scalar_set_b32(&s_privkey, &(privkeys[32 * i]), NULL);

        /* Reject the privkey if it's zero or has reduced to zero. */
        /* Mark the corresponding Jacobian pubkey as infinity so we know to skip this key later. */
        if ( secp256k1_scalar_is_zero(&s_privkey) ) {
            scr->gej[i].infinity = 1;
            continue;
        }


        /* Multiply the private key by the generator point. */
        if ( bmul != NULL ) {
            /* Multiplication using larger, faster, precomputed tables. */
            secp256k1_ecmult_big(bmul, &(scr->gej[i]), &s_privkey);
        } else {
            /* Multiplication using default implementation. */
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &(scr->gej[i]), &s_privkey);
        }

        /* If the result is the point at infinity, the pubkey is invalid. */
        if ( scr->gej[i].infinity ) { continue; }


        /* Save the Jacobian pubkey's Z coordinate for batch inversion. */
        scr->fe_in[out_keys] = scr->gej[i].z;
        out_keys++;
    }


    /* Assuming we have at least one non-infinite Jacobian pubkey. */
    if ( out_keys > 0 ) {
        /* Invert all Jacobian public keys' Z values in one go. */
        secp256k1_fe_inv_all_var(out_keys, scr->fe_out, scr->fe_in);
    }


    /* Using the inverted Z values, convert each Jacobian public key to affine, */
    /*   then serialize the affine version to the pubkey buffer.                */
    out_keys = 0;

    for ( i = 0; i < key_count; i++) {
        /* Skip inverting infinite values. */
        /* The corresponding pubkey is already filled with \0 bytes from earlier. */
        if ( scr->gej[i].infinity ) {
            continue;
        }

        /* Otherwise, load the next inverted Z value and convert the pubkey to affine coordinates. */
        secp256k1_ge_set_gej_zinv(&ge_pubkey, &(scr->gej[i]), &(scr->fe_out[out_keys]));

        /* Serialize the public key into the requested format. */
        secp256k1_eckey_pubkey_serialize(&ge_pubkey, &(pubkeys[pubkey_size * i]), &dummy, compressed);
        out_keys++;
    }


    /* Returning the number of successfully converted private keys. */
    return out_keys;
}


#endif
