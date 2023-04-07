/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_DEBUG_H_
#define _SECP256K1_DEBUG_H_


#include <stdio.h>
#include "group.h"
#include "field.h"



static void secp256k1_dump_fe(secp256k1_fe *fe) {
    size_t i;
    unsigned char *raw_ptr = (unsigned char *)fe;

    VERIFY_CHECK(fe != NULL);

    secp256k1_fe_normalize_var(fe);
    for ( i = 0; i < sizeof(secp256k1_fe); i++, raw_ptr++ ) {
        printf("%02x ", *raw_ptr & 0xFF);
    }
}


static void secp256k1_dump_ge(secp256k1_ge *ge, char *name) {
    VERIFY_CHECK(ge != NULL);

    if ( name != NULL ) {
        printf("ge dump of %s\n", name);
    } else {
        printf("ge dump of %p\n", ge);
    }
    printf("  v = %d", secp256k1_ge_is_valid_var(ge));  printf("\n");
    printf("  i = %d", ge->infinity);                   printf("\n");
    printf("  x = "); secp256k1_dump_fe(&ge->x);        printf("\n");
    printf("  y = "); secp256k1_dump_fe(&ge->y);        printf("\n");
}


static void secp256k1_dump_gej(secp256k1_gej *gej, char *name) {
    VERIFY_CHECK(gej != NULL);

    if ( name != NULL ) {
        printf("gej dump of %s\n", name);
    } else {
        printf("gej dump of %p\n", gej);
    }
    printf("  i = %d", gej->infinity);                  printf("\n");
    printf("  x = "); secp256k1_dump_fe(&gej->x);       printf("\n");
    printf("  y = "); secp256k1_dump_fe(&gej->y);       printf("\n");
    printf("  z = "); secp256k1_dump_fe(&gej->z);       printf("\n");
}

#endif