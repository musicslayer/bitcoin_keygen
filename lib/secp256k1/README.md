libsecp256k1_fast_unsafe
========================

DO NOT USE THIS LIBRARY IF SAFETY OR SECURITY IS A CONCERN!
-----------------------------------------------------------

This is a modified version of the [secp256k1 library](https://github.com/bitcoin-core/secp256k1), altered to run as quickly as possible with **absolutely no regard for security**.  
As a result, these modifications allow for public key creations up to 20x faster than the original implementation.

The modifications include:
- All constant-time functions have been replaced with their variable-time counterparts.
- Added a module which supports [variably sized precomputed tables](src/ecmult_big.h) for faster scalar point multiplication.
  - Allows for trading memory consumption and precomputation for considerably faster speeds.
  - Doesn't include a blinding value to allow for occasional shortcuts to be taken.
- Added a module which supports batched creation of serialized public keys from private keys.
  - Each batch only requires a single Z-coordinate inversion instead of one inversion per output key.
  - Works with the default or variable sized precomputed tables.
- Removed all memory clearing of secret values.

Again, **do not use this library if safety or security is a concern!**  
All safety and security features have been disabled for the sake of performance.  
You have been warned.



### Variably Sized Precomputed Tables

The default secp256k1 library uses a fixed-size precomputed table which uses a 4-bit window and a blinding value.  
This library adds support for [variably sized precomputed tables](src/ecmult_big.h) with a user-defined window size between 4 and 62 bits.

The following is a sample of various window sizes, their memory requirements, and number of rows:

| Window Size | Final Memory | Setup Memory* | Table Rows** |
| ----------: | -----------: | ------------: | -----------: |
|      4 bits |      <0.1 MB |       <0.1 MB |    65 rows   |
|      8 bits |       0.3 MB |       <0.1 MB |    33 rows   |
|     10 bits |       0.8 MB |        0.1 MB |    26 rows   |
|     12 bits |       2.6 MB |        0.3 MB |    22 rows   |
|     14 bits |       9.0 MB |        1.3 MB |    19 rows   |
|     16 bits |      32.0 MB |        5.1 MB |    17 rows   |
|     17 bits |      60.0 MB |       10.3 MB |    16 rows   |
|     18 bits |     112.0 MB |       20.5 MB |    15 rows   |
|     19 bits |     208.0 MB |       41.0 MB |    14 rows   |
|     20 bits |     388.0 MB |       82.0 MB |    13 rows   |
|     22 bits |    1409.0 MB |      328.0 MB |    12 rows   |
|     24 bits |    5124.0 MB |     1312.2 MB |    11 rows   |

\*: Setup memory is freed after the precomputed table has been created.  
\*\*: As the number of table rows decreases, the maximum number of point additions per scalar multiplication decreases.  The actual number of point additions may be less.

A more full explanation can be found in [`ecmult_big.h`](src/ecmult_big.h) and [`ecmult_big_impl.h`](src/ecmult_big_impl.h).



### Batched Key Serialization

The creation of an ECC public key usually requires converting the result from a Jacobian coordinate to an affine coordinate.  This operation requires calculating the [modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of the Jacobian point's Z-coordinate using the computationally expensive [extended Euclidian algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm).  Traditionally, ECC public keys are created one at a time, each requiring its own Z-coordinate inversion.  By batching the key creations, the number of inversions is decreased from *one per key* to *one per batch*.

This library adds support for creating batches of serialized public keys.  Furthermore, these batched creations can leverage the variably sized precomputed tables, leading to considerable performance gains.



### Sample Benchmarks

The below benchmarks were run single-threaded on an Intel Core i5-3210M processor.  
The benchmarks were compiled and run under 32-bit and 64-bit versions of Cygwin.  
Your benchmark results may vary (see [`bench_privkey.c`](src/bench_privkey.c) for benchmark instructions).

[All 32-bit benchmark results](32bit_benchmarks.png)  
Best 32-bit result:
- **Table Size:** 22 bits
- **Batch Size:** 8 elements
- **Result: ~45k keys/second**

[All 64-bit benchmark results](64bit_benchmarks.png)  
Best 64-bit result:
- **Table Size:** 22 bits
- **Batch Size:** 512 elements
- **Result: ~152k keys/second**


---------

libsecp256k1
========================

Optimized C library for EC operations on curve secp256k1.

This library is a work in progress and is being used to research best practices. Use at your own risk.

Features:
* secp256k1 ECDSA signing/verification and key generation.
* Adding/multiplying private/public keys.
* Serialization/parsing of private keys, public keys, signatures.
* Constant time, constant memory access signing and pubkey generation.
* Derandomized DSA (via RFC6979 or with a caller provided function.)
* Very efficient implementation.

Implementation details
----------------------

* General
  * No runtime heap allocation.
  * Extensive testing infrastructure.
  * Structured to facilitate review and analysis.
  * Intended to be portable to any system with a C89 compiler and uint64_t support.
  * Expose only higher level interfaces to minimize the API surface and improve application security. ("Be difficult to use insecurely.")
* Field operations
  * Optimized implementation of arithmetic modulo the curve's field size (2^256 - 0x1000003D1).
    * Using 5 52-bit limbs (including hand-optimized assembly for x86_64, by Diederik Huys).
    * Using 10 26-bit limbs.
  * Field inverses and square roots using a sliding window over blocks of 1s (by Peter Dettman).
* Scalar operations
  * Optimized implementation without data-dependent branches of arithmetic modulo the curve's order.
    * Using 4 64-bit limbs (relying on __int128 support in the compiler).
    * Using 8 32-bit limbs.
* Group operations
  * Point addition formula specifically simplified for the curve equation (y^2 = x^3 + 7).
  * Use addition between points in Jacobian and affine coordinates where possible.
  * Use a unified addition/doubling formula where necessary to avoid data-dependent branches.
  * Point/x comparison without a field inversion by comparison in the Jacobian coordinate space.
* Point multiplication for verification (a*P + b*G).
  * Use wNAF notation for point multiplicands.
  * Use a much larger window for multiples of G, using precomputed multiples.
  * Use Shamir's trick to do the multiplication with the public key and the generator simultaneously.
  * Optionally (off by default) use secp256k1's efficiently-computable endomorphism to split the P multiplicand into 2 half-sized ones.
* Point multiplication for signing
  * Use a precomputed table of multiples of powers of 16 multiplied with the generator, so general multiplication becomes a series of additions.
  * Access the table with branch-free conditional moves so memory access is uniform.
  * No data-dependent branches
  * The precomputed tables add and eventually subtract points for which no known scalar (private key) is known, preventing even an attacker with control over the private key used to control the data internally.

Build steps
-----------

libsecp256k1 is built using autotools:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ ./tests
    $ sudo make install  # optional
