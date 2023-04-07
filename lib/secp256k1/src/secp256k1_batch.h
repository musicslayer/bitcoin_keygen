/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BATCH_H_
#define _SECP256K1_BATCH_H_

#include <stddef.h>
#include "secp256k1.c"
#include "ecmult_big.h"


/** Opaque data structure that holds scratch memory for usage in batch computations. */
typedef struct secp256k1_scratch_struct secp256k1_scratch;



/** Create a secp256k1 scratch object.
 *
 *  Returns: a newly created scratch object.
 *  Args:   ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  In:     size:   maximum number of items the scratch object will store
 */
SECP256K1_API secp256k1_scratch* secp256k1_scratch_create(
    const secp256k1_context* ctx,
    const size_t size
) SECP256K1_WARN_UNUSED_RESULT;


/** Destroy a secp256k1 scratch object.
 *
 *  The scratch pointer may not be used afterwards.
 *  Args:   ctx:    an existing context to destroy (cannot be NULL)
 */
SECP256K1_API void secp256k1_scratch_destroy(
    secp256k1_scratch* scr
);


/** Creates and serializes a single public key from a single private key.
 *
 *  Returns: number of public keys created, invalid keys will be all \0 bytes
 *  Args:   ctx:        pointer to a context object, initialized for signing (cannot be NULL)
 *          bmul:       pointer to an optional ecmult big context for faster ecmult computations
 *  Out:    pubkey:     pointer to an array sized to hold the serialized pubkey (33 or 65 bytes, cannot be NULL)
 *  In:     privkey:    pointer to a 32-byte private key (cannot be NULL)
 *          compressed: compression flag, 0 for uncompressed output (65 bytes), 1 for compressed (33 bytes)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT size_t secp256k1_ec_pubkey_create_serialized(
    const secp256k1_context *ctx,
    const secp256k1_ecmult_big_context *bmul,
    unsigned char *pubkey,
    const unsigned char *privkey,
    const unsigned int compressed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);


/** Creates and serializes a multiple public keys from a multiple private keys.
 *
 *  Returns: number of public keys created, invalid keys will be all \0 bytes
 *  Args:   ctx:        pointer to a context object, initialized for signing (cannot be NULL)
 *          bmul:       pointer to an optional ecmult big context for faster ecmult computations
 *          scr:        pointer to a scratch object, initialized to hold at least key_count items (cannot be NULL)
 *  Out:    pubkeys:    pointer to an array sized to hold at least key_count serialized pubkeys (33 or 65 bytes each, cannot be NULL)
 *  In:     privkeys:   pointer to key_count 32-byte private keys (cannot be NULL)
 *          key_count:  number of private keys
 *          compressed: compression flag, 0 for uncompressed output (65 bytes), 1 for compressed (33 bytes)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT size_t secp256k1_ec_pubkey_create_serialized_batch(
    const secp256k1_context *ctx,
    const secp256k1_ecmult_big_context *bmul,
    secp256k1_scratch* scr,
    unsigned char *pubkeys,
    const unsigned char *privkeys,
    const size_t key_count,
    const unsigned int compressed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);


#endif
