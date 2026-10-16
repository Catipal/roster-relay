// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * lwIP's platform header for BPS (lwip/arch.h includes it). lwIP's own
 * defaults cover the types, the printf formats and the diagnostics; what is
 * set here is what they would get wrong for this node.
 */
#ifndef BPS_LWIP_ARCH_CC_H
#define BPS_LWIP_ARCH_CC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initial sequence numbers and ports come from the node's own generator
 * (overlay/netstack.cpp) rather than rand(), which is predictable and, on
 * some platforms, shared with whatever else in the process calls it.
 */
uint32_t bps_lwip_rand(void);
#define LWIP_RAND() ((u32_t)bps_lwip_rand())

#ifdef __cplusplus
}
#endif

/* The byte order the compiler is building for, not lwIP's little-endian guess. */
#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif

#endif /* BPS_LWIP_ARCH_CC_H */
