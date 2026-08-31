#ifndef SLH_CONFIG_H
#define SLH_CONFIG_H

/*
 * ============================================================
 * Hash family
 * ============================================================
 */

#define SLH_HASH_SHA2   1
#define SLH_HASH_SHAKE  2


/*
 * ============================================================
 * SELECT CONFIGURATION HERE
 * ============================================================
 *
 * Examples:
 *
 * SHA2-128:
 *
 *   #define SLH_HASH_FAMILY SLH_HASH_SHA2
 *   #define SLH_N 16
 *
 * SHA2-192:
 *
 *   #define SLH_HASH_FAMILY SLH_HASH_SHA2
 *   #define SLH_N 24
 *
 * SHA2-256:
 *
 *   #define SLH_HASH_FAMILY SLH_HASH_SHA2
 *   #define SLH_N 32
 *
 * SHAKE-128:
 *
 *   #define SLH_HASH_FAMILY SLH_HASH_SHAKE
 *   #define SLH_N 16
 *
 * ...
 */

#define SLH_HASH_FAMILY SLH_HASH_SHA2
#define SLH_N 32


#if (SLH_N != 16) && \
    (SLH_N != 24) && \
    (SLH_N != 32)
#error "SLH_N must be 16, 24 or 32"
#endif


#if (SLH_HASH_FAMILY != SLH_HASH_SHA2) && \
    (SLH_HASH_FAMILY != SLH_HASH_SHAKE)
#error "Invalid SLH_HASH_FAMILY"
#endif


#define SLH_N_WORDS (SLH_N / 4)


#if SLH_HASH_FAMILY == SLH_HASH_SHA2

#define SLH_ADDR_HASH_BYTES   22
#define SLH_CHAIN_OFFSET      17
#define SLH_HASH_OFFSET       21

#else

#define SLH_ADDR_HASH_BYTES   32
#define SLH_CHAIN_OFFSET      27
#define SLH_HASH_OFFSET       31

#endif


#endif
